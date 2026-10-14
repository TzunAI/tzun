/**
 * Mandates (Record §9.6): the `mandates`, `mandate_totals` and
 * `mandate_events` tables, as a storage extension.
 *
 *   - `mandates`: one row per issued mandate. Its digests, document,
 *     statement, assertion, limits, window and issuance record never change;
 *     `state` moves only from `open` (to `revoked`, `superseded` or
 *     `expired`), and `used` changes only by +1 while the mandate is open.
 *   - `mandate_totals`: one row per cap, `(mandate_id, cap)`; its maximum
 *     never changes and its total only increases, never past the maximum.
 *   - `mandate_events`: insert-only; one `tzun-mandate-event/1` body per state
 *     change, its canonical bytes and their SHA-256.
 *
 * Every write rides on the store of the record that causes it, in the
 * storing transaction, decided by `planMandateWrite` (`mandate-sql.ts`): a
 * capture under a mandate claims its slot and running totals by
 * compare-and-swap (`StoreOptions.mandateClaim`); an issuance record inserts
 * the mandate (`mandateIssue`); a revocation record, or a successor's
 * issuance record, closes it (`mandateRevoke`). Expiry captures no record
 * and is `expireMandate()`, a transaction of its own.
 *
 * Lock order: on Postgres the `lock` hook takes the mandate row
 * (`SELECT … FOR UPDATE`) before `store()` takes the chain's append lock, and
 * `expireMandate()` takes only the mandate row, so no two paths take the two
 * locks in opposite orders. SQLite's IMMEDIATE transaction and the memory
 * adapter's synchronous section exclude every other writer.
 *
 * The methods: `getMandate(idOrDigest)` (a mandate by its id, or by its
 * 64-hex digest, as a successor's document names its predecessor),
 * `getMandateTotals`, `listMandateEvents` (oldest first) and `expireMandate`.
 * `listMandates` lists mandates by state and by the end of their window, in
 * mandate id order (`sqliteListMandates`, `postgresListMandates`,
 * `memoryListMandates`, over the index `mandates_by_state_not_after`).
 */
import type Database from 'better-sqlite3';
import type { Pool, PoolClient } from 'pg';
import type { MandateEventRow, MandateExpireStore, MandateRow } from '@tzun/engine';
import type { StorageExtension, StoreWrite } from '../extensions';
import {
  MandateStoreRefusalError,
  POSTGRES_MANDATE_SQL as PG,
  SQLITE_MANDATE_SQL as SQL,
  assertChanged,
  issuedKeyOf,
  listMandatesQuery,
  mandateEventRowOf,
  mandateListed,
  mandateListPage,
  mandateIdsOf,
  mandateInsertValues,
  mandateRowOf,
  mandateStateOf,
  planMandateExpiry,
  planMandateWrite,
  totalsMapOf,
  type MandateDbRow,
  type MandateListFilter,
  type MandateListPage,
  type MandateSnapshot,
  type MandateStateRow,
  type MandateTotalRow,
  type MandateWritePlan,
} from '../mandate-sql';

// ── DDL ────────────────────────────────────────────────────────────────────

export const SQLITE_MANDATES_DDL = `
  CREATE TABLE IF NOT EXISTS mandates (
    mandate_id TEXT PRIMARY KEY,
    mandate_digest TEXT NOT NULL UNIQUE,
    document_bytes TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    statement_digest TEXT NOT NULL,
    assertion_json TEXT NOT NULL,
    assertion_digest TEXT NOT NULL,
    assertion_timestamp TEXT,
    state TEXT NOT NULL CHECK (state IN ('open', 'revoked', 'superseded', 'expired')),
    used INTEGER NOT NULL CHECK (used >= 0),
    max_records INTEGER CHECK (max_records IS NULL OR max_records >= 1),
    not_before TEXT,
    not_after TEXT,
    issuance_evidence_id TEXT NOT NULL UNIQUE,
    issuance_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (max_records IS NULL OR used <= max_records)
  );
  CREATE TRIGGER IF NOT EXISTS mandates_guard_update
    BEFORE UPDATE ON mandates
    BEGIN
      SELECT RAISE(ABORT, 'mandates: only state and used change')
        WHERE NEW.mandate_id IS NOT OLD.mandate_id OR NEW.mandate_digest IS NOT OLD.mandate_digest
           OR NEW.document_bytes IS NOT OLD.document_bytes OR NEW.statement_json IS NOT OLD.statement_json
           OR NEW.statement_digest IS NOT OLD.statement_digest OR NEW.assertion_json IS NOT OLD.assertion_json
           OR NEW.assertion_digest IS NOT OLD.assertion_digest OR NEW.assertion_timestamp IS NOT OLD.assertion_timestamp
           OR NEW.max_records IS NOT OLD.max_records OR NEW.not_before IS NOT OLD.not_before
           OR NEW.not_after IS NOT OLD.not_after OR NEW.issuance_evidence_id IS NOT OLD.issuance_evidence_id
           OR NEW.issuance_digest IS NOT OLD.issuance_digest OR NEW.created_at IS NOT OLD.created_at;
      SELECT RAISE(ABORT, 'mandates: state moves only from open')
        WHERE NEW.state IS NOT OLD.state
          AND NOT (OLD.state = 'open' AND NEW.state IN ('revoked', 'superseded', 'expired'));
      SELECT RAISE(ABORT, 'mandates: used changes only by +1 while the mandate is open')
        WHERE NOT (NEW.used = OLD.used OR (NEW.used = OLD.used + 1 AND OLD.state = 'open' AND NEW.state = 'open'));
    END;
  CREATE TRIGGER IF NOT EXISTS mandates_block_delete
    BEFORE DELETE ON mandates
    BEGIN SELECT RAISE(ABORT, 'mandates rows are never deleted'); END;
  CREATE INDEX IF NOT EXISTS mandates_by_state_not_after ON mandates (state, not_after);
  CREATE TABLE IF NOT EXISTS mandate_totals (
    mandate_id TEXT NOT NULL,
    cap TEXT NOT NULL,
    max INTEGER NOT NULL CHECK (max >= 0),
    total INTEGER NOT NULL CHECK (total >= 0),
    PRIMARY KEY (mandate_id, cap),
    CHECK (total <= max)
  );
  CREATE TRIGGER IF NOT EXISTS mandate_totals_guard_update
    BEFORE UPDATE ON mandate_totals
    BEGIN
      SELECT RAISE(ABORT, 'mandate_totals: only total changes, and only upward')
        WHERE NEW.mandate_id IS NOT OLD.mandate_id OR NEW.cap IS NOT OLD.cap OR NEW.max IS NOT OLD.max
           OR NEW.total < OLD.total;
    END;
  CREATE TRIGGER IF NOT EXISTS mandate_totals_block_delete
    BEFORE DELETE ON mandate_totals
    BEGIN SELECT RAISE(ABORT, 'mandate_totals rows are never deleted'); END;
  CREATE TABLE IF NOT EXISTS mandate_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mandate_id TEXT NOT NULL,
    event TEXT NOT NULL CHECK (event IN ('issued', 'revoked', 'superseded', 'expired')),
    canonical TEXT NOT NULL,
    digest TEXT NOT NULL,
    recorded_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS mandate_events_by_mandate ON mandate_events (mandate_id, id);
  CREATE TRIGGER IF NOT EXISTS mandate_events_block_update
    BEFORE UPDATE ON mandate_events
    BEGIN SELECT RAISE(ABORT, 'mandate_events rows are insert-only (UPDATE refused)'); END;
  CREATE TRIGGER IF NOT EXISTS mandate_events_block_delete
    BEFORE DELETE ON mandate_events
    BEGIN SELECT RAISE(ABORT, 'mandate_events rows are insert-only (DELETE refused)'); END;
`;

export const POSTGRES_MANDATES_DDL = `
  CREATE TABLE IF NOT EXISTS mandates (
    mandate_id TEXT PRIMARY KEY,
    mandate_digest TEXT NOT NULL UNIQUE,
    document_bytes TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    statement_digest TEXT NOT NULL,
    assertion_json TEXT NOT NULL,
    assertion_digest TEXT NOT NULL,
    assertion_timestamp TEXT,
    state TEXT NOT NULL CHECK (state IN ('open', 'revoked', 'superseded', 'expired')),
    used BIGINT NOT NULL CHECK (used >= 0),
    max_records BIGINT CHECK (max_records IS NULL OR max_records >= 1),
    not_before TEXT,
    not_after TEXT,
    issuance_evidence_id TEXT NOT NULL UNIQUE,
    issuance_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (max_records IS NULL OR used <= max_records)
  );
  CREATE OR REPLACE FUNCTION mandates_guard()
  RETURNS TRIGGER AS $$
  BEGIN
    IF TG_OP <> 'UPDATE' THEN
      RAISE EXCEPTION 'mandates rows are never deleted (% refused)', TG_OP;
    END IF;
    IF NEW.mandate_id IS DISTINCT FROM OLD.mandate_id OR NEW.mandate_digest IS DISTINCT FROM OLD.mandate_digest
       OR NEW.document_bytes IS DISTINCT FROM OLD.document_bytes OR NEW.statement_json IS DISTINCT FROM OLD.statement_json
       OR NEW.statement_digest IS DISTINCT FROM OLD.statement_digest OR NEW.assertion_json IS DISTINCT FROM OLD.assertion_json
       OR NEW.assertion_digest IS DISTINCT FROM OLD.assertion_digest
       OR NEW.assertion_timestamp IS DISTINCT FROM OLD.assertion_timestamp
       OR NEW.max_records IS DISTINCT FROM OLD.max_records OR NEW.not_before IS DISTINCT FROM OLD.not_before
       OR NEW.not_after IS DISTINCT FROM OLD.not_after OR NEW.issuance_evidence_id IS DISTINCT FROM OLD.issuance_evidence_id
       OR NEW.issuance_digest IS DISTINCT FROM OLD.issuance_digest OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'mandates: only state and used change';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state
       AND NOT (OLD.state = 'open' AND NEW.state IN ('revoked', 'superseded', 'expired')) THEN
      RAISE EXCEPTION 'mandates: state moves only from open';
    END IF;
    IF NOT (NEW.used = OLD.used OR (NEW.used = OLD.used + 1 AND OLD.state = 'open' AND NEW.state = 'open')) THEN
      RAISE EXCEPTION 'mandates: used changes only by +1 while the mandate is open';
    END IF;
    RETURN NEW;
  END;
  $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
  DROP TRIGGER IF EXISTS mandates_guard_trigger ON mandates;
  CREATE TRIGGER mandates_guard_trigger
    BEFORE UPDATE OR DELETE ON mandates
    FOR EACH ROW EXECUTE FUNCTION mandates_guard();
  CREATE INDEX IF NOT EXISTS mandates_by_state_not_after ON mandates (state, not_after);
  CREATE TABLE IF NOT EXISTS mandate_totals (
    mandate_id TEXT NOT NULL,
    cap TEXT NOT NULL,
    max BIGINT NOT NULL CHECK (max >= 0),
    total BIGINT NOT NULL CHECK (total >= 0),
    PRIMARY KEY (mandate_id, cap),
    CHECK (total <= max)
  );
  CREATE OR REPLACE FUNCTION mandate_totals_guard()
  RETURNS TRIGGER AS $$
  BEGIN
    IF TG_OP <> 'UPDATE' THEN
      RAISE EXCEPTION 'mandate_totals rows are never deleted (% refused)', TG_OP;
    END IF;
    IF NEW.mandate_id IS DISTINCT FROM OLD.mandate_id OR NEW.cap IS DISTINCT FROM OLD.cap
       OR NEW.max IS DISTINCT FROM OLD.max OR NEW.total < OLD.total THEN
      RAISE EXCEPTION 'mandate_totals: only total changes, and only upward';
    END IF;
    RETURN NEW;
  END;
  $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
  DROP TRIGGER IF EXISTS mandate_totals_guard_trigger ON mandate_totals;
  CREATE TRIGGER mandate_totals_guard_trigger
    BEFORE UPDATE OR DELETE ON mandate_totals
    FOR EACH ROW EXECUTE FUNCTION mandate_totals_guard();
  CREATE TABLE IF NOT EXISTS mandate_events (
    id BIGSERIAL PRIMARY KEY,
    mandate_id TEXT NOT NULL,
    event TEXT NOT NULL CHECK (event IN ('issued', 'revoked', 'superseded', 'expired')),
    canonical TEXT NOT NULL,
    digest TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS mandate_events_by_mandate ON mandate_events (mandate_id, id);
  CREATE OR REPLACE FUNCTION mandate_events_block_mutation()
  RETURNS TRIGGER AS $$
  BEGIN
    RAISE EXCEPTION '% rows are insert-only (% refused)', TG_TABLE_NAME, TG_OP;
  END;
  $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
  DROP TRIGGER IF EXISTS mandate_events_block_mutation_trigger ON mandate_events;
  CREATE TRIGGER mandate_events_block_mutation_trigger
    BEFORE UPDATE OR DELETE ON mandate_events
    FOR EACH ROW EXECUTE FUNCTION mandate_events_block_mutation();
  DROP TRIGGER IF EXISTS mandates_block_truncate_trigger ON mandates;
  CREATE TRIGGER mandates_block_truncate_trigger
    BEFORE TRUNCATE ON mandates
    FOR EACH STATEMENT EXECUTE FUNCTION mandate_events_block_mutation();
  DROP TRIGGER IF EXISTS mandate_totals_block_truncate_trigger ON mandate_totals;
  CREATE TRIGGER mandate_totals_block_truncate_trigger
    BEFORE TRUNCATE ON mandate_totals
    FOR EACH STATEMENT EXECUTE FUNCTION mandate_events_block_mutation();
  DROP TRIGGER IF EXISTS mandate_events_block_truncate_trigger ON mandate_events;
  CREATE TRIGGER mandate_events_block_truncate_trigger
    BEFORE TRUNCATE ON mandate_events
    FOR EACH STATEMENT EXECUTE FUNCTION mandate_events_block_mutation();
`;

// ── SQLite ─────────────────────────────────────────────────────────────────

function sqliteSnapshot(db: Database.Database, write: Pick<StoreWrite, 'options'>, ids: readonly string[]): MandateSnapshot {
  const rows = new Map<string, MandateStateRow>();
  const totals = new Map<string, Map<string, MandateTotalRow>>();
  for (const id of ids) {
    const row = db.prepare(SQL.selectById).get(id) as MandateDbRow | undefined;
    if (row) rows.set(id, mandateStateOf(mandateRowOf(row)));
    totals.set(id, totalsMapOf(db.prepare(SQL.selectTotals).all(id) as Array<{ cap: string; max: number; total: number }>));
  }
  const issued = issuedKeyOf(write);
  const issueTaken = issued !== null && db.prepare(SQL.issueTaken).get(issued.mandateId, issued.mandateDigest) !== undefined;
  return { rows, totals, issueTaken };
}

function sqliteApply(db: Database.Database, plan: MandateWritePlan): void {
  if (plan.claim) {
    const { mandateId, expectUsed, caps } = plan.claim;
    assertChanged(db.prepare(SQL.claimSlot).run(mandateId, expectUsed).changes, mandateId, 'slot count');
    for (const c of caps) {
      assertChanged(db.prepare(SQL.claimCap).run(c.newTotal, mandateId, c.cap, c.expectTotal, c.newTotal).changes, mandateId, `total of cap ${c.cap}`);
    }
  }
  if (plan.transition) {
    const { mandateId, newState, expectUsed } = plan.transition;
    assertChanged(db.prepare(SQL.transition).run(newState, mandateId, expectUsed).changes, mandateId, 'state');
  }
  if (plan.insert) {
    const { record, caps } = plan.insert;
    db.prepare(SQL.insertMandate).run(...mandateInsertValues(record));
    for (const c of caps) db.prepare(SQL.insertCap).run(record.mandateId, c.cap, c.max);
  }
  const at = new Date().toISOString();
  for (const e of plan.events) db.prepare(SQL.insertEvent).run(e.mandateId, e.body.event, e.canonical, e.digest, at);
}

function sqliteGetMandate(db: Database.Database, idOrDigest: string): MandateRow | null {
  const row = db.prepare(SQL.selectByIdOrDigest).get(idOrDigest, idOrDigest) as MandateDbRow | undefined;
  return row ? mandateRowOf(row) : null;
}

/** A page of the mandates `filter` selects, in mandate id order (`listMandates`). */
export function sqliteListMandates(db: Database.Database, filter?: MandateListFilter): MandateListPage {
  const q = listMandatesQuery(filter);
  const rows = db.prepare(SQL.list).all(q.state, q.state, q.notAfterBefore, q.notAfterBefore, q.after, q.limit + 1) as MandateDbRow[];
  return mandateListPage(rows.map(mandateRowOf), q);
}

// ── Postgres ───────────────────────────────────────────────────────────────

async function postgresSnapshot(client: PoolClient, write: Pick<StoreWrite, 'options'>, ids: readonly string[]): Promise<MandateSnapshot> {
  const rows = new Map<string, MandateStateRow>();
  const totals = new Map<string, Map<string, MandateTotalRow>>();
  for (const id of ids) {
    const row = (await client.query<MandateDbRow>(PG.selectByIdForUpdate, [id])).rows[0];
    if (row) rows.set(id, mandateStateOf(mandateRowOf(row)));
    const caps = await client.query<{ cap: string; max: string; total: string }>(PG.selectTotals, [id]);
    totals.set(id, totalsMapOf(caps.rows));
  }
  const issued = issuedKeyOf(write);
  const issueTaken = issued !== null && (await client.query(PG.issueTaken, [issued.mandateId, issued.mandateDigest])).rows.length > 0;
  return { rows, totals, issueTaken };
}

/** A unique violation on `mandates` (two issuers of one mandate racing): the second is refused as already issued. */
function translateIssueError(err: unknown, mandateId: string): unknown {
  const e = err as { code?: unknown; table?: unknown };
  if (e && e.code === '23505' && e.table === 'mandates') {
    return new MandateStoreRefusalError('mandate_already_issued', mandateId, 'document.mandateId', `a mandate with the id or digest of mandate ${mandateId} is already issued`);
  }
  return err;
}

/** A page of the mandates `filter` selects, in mandate id order (`listMandates`). */
export async function postgresListMandates(pool: Pool, filter?: MandateListFilter): Promise<MandateListPage> {
  const q = listMandatesQuery(filter);
  const rows = (await pool.query<MandateDbRow>(PG.list, [q.state, q.notAfterBefore, q.after, q.limit + 1])).rows;
  return mandateListPage(rows.map(mandateRowOf), q);
}

async function postgresApply(client: PoolClient, plan: MandateWritePlan): Promise<void> {
  if (plan.claim) {
    const { mandateId, expectUsed, caps } = plan.claim;
    assertChanged((await client.query(PG.claimSlot, [mandateId, expectUsed])).rowCount ?? 0, mandateId, 'slot count');
    for (const c of caps) {
      assertChanged((await client.query(PG.claimCap, [c.newTotal, mandateId, c.cap, c.expectTotal])).rowCount ?? 0, mandateId, `total of cap ${c.cap}`);
    }
  }
  if (plan.transition) {
    const { mandateId, newState, expectUsed } = plan.transition;
    assertChanged((await client.query(PG.transition, [newState, mandateId, expectUsed])).rowCount ?? 0, mandateId, 'state');
  }
  if (plan.insert) {
    const { record, caps } = plan.insert;
    try {
      await client.query(PG.insertMandate, mandateInsertValues(record));
    } catch (err) {
      throw translateIssueError(err, record.mandateId);
    }
    for (const c of caps) await client.query(PG.insertCap, [record.mandateId, c.cap, c.max]);
  }
  for (const e of plan.events) await client.query(PG.insertEvent, [e.mandateId, e.body.event, e.canonical, e.digest]);
}

// ── Memory ─────────────────────────────────────────────────────────────────

interface MemoryMandatesState {
  rows: Map<string, MandateRow>;
  byDigest: Map<string, string>;
  totals: Map<string, Map<string, MandateTotalRow>>;
  events: Map<string, MandateEventRow[]>;
}

function memorySnapshot(state: MemoryMandatesState, write: Pick<StoreWrite, 'options'>, ids: readonly string[]): MandateSnapshot {
  const rows = new Map<string, MandateStateRow>();
  const totals = new Map<string, Map<string, MandateTotalRow>>();
  for (const id of ids) {
    const row = state.rows.get(id);
    if (row) rows.set(id, mandateStateOf(row));
    totals.set(id, new Map([...(state.totals.get(id) ?? new Map()).entries()].map(([cap, t]) => [cap, { ...t }])));
  }
  const issued = issuedKeyOf(write);
  const issueTaken = issued !== null && (state.rows.has(issued.mandateId) || state.byDigest.has(issued.mandateDigest));
  return { rows, totals, issueTaken };
}

/** Apply a plan already decided over this state in the same synchronous section: no guard can fail. */
function memoryApply(state: MemoryMandatesState, plan: MandateWritePlan): void {
  if (plan.claim) {
    const row = state.rows.get(plan.claim.mandateId)!;
    row.used += 1;
    const totals = state.totals.get(plan.claim.mandateId)!;
    for (const c of plan.claim.caps) totals.get(c.cap)!.total = c.newTotal;
  }
  if (plan.transition) state.rows.get(plan.transition.mandateId)!.state = plan.transition.newState;
  if (plan.insert) {
    const { record, caps } = plan.insert;
    state.rows.set(record.mandateId, { ...record });
    state.byDigest.set(record.mandateDigest, record.mandateId);
    state.totals.set(record.mandateId, new Map(caps.map((c) => [c.cap, { max: c.max, total: 0 }])));
  }
  for (const e of plan.events) {
    const list = state.events.get(e.mandateId) ?? [];
    list.push({ mandateId: e.mandateId, body: JSON.parse(e.canonical), canonical: e.canonical, digest: e.digest });
    state.events.set(e.mandateId, list);
  }
}

function memoryPlan(state: MemoryMandatesState, write: StoreWrite): MandateWritePlan | null {
  return planMandateWrite(write, memorySnapshot(state, write, mandateIdsOf(write)));
}

/** A page of the mandates `filter` selects, in mandate id order (`listMandates`), over a memory adapter's mandate state. */
export function memoryListMandates(state: { rows: ReadonlyMap<string, MandateRow> }, filter?: MandateListFilter): MandateListPage {
  const q = listMandatesQuery(filter);
  const rows = [...state.rows.values()]
    .filter((row) => mandateListed(row, q))
    .sort((a, b) => (a.mandateId < b.mandateId ? -1 : a.mandateId > b.mandateId ? 1 : 0))
    .slice(0, q.limit + 1)
    .map((row) => ({ ...row }));
  return mandateListPage(rows, q);
}

// ── The extension ──────────────────────────────────────────────────────────

/** The mandate tables, their store() hooks, and `getMandate`, `getMandateTotals`, `listMandateEvents`, `expireMandate`, `listMandates`. */
export const mandatesExtension: StorageExtension = {
  name: 'mandates',
  sqlite: {
    migrate(db) {
      db.exec(SQLITE_MANDATES_DDL);
    },
    beforeInsert(db, write) {
      const plan = planMandateWrite(write, sqliteSnapshot(db, write, mandateIdsOf(write)));
      if (plan) sqliteApply(db, plan);
    },
    methods(db) {
      return {
        async getMandate(mandateId: string): Promise<MandateRow | null> {
          return sqliteGetMandate(db, mandateId);
        },
        async getMandateTotals(mandateId: string): Promise<Record<string, number>> {
          const rows = db.prepare(SQL.selectTotals).all(mandateId) as Array<{ cap: string; total: number }>;
          return Object.fromEntries(rows.map((r) => [r.cap, Number(r.total)]));
        },
        async listMandateEvents(mandateId: string): Promise<MandateEventRow[]> {
          const rows = db.prepare(SQL.selectEvents).all(mandateId) as Array<{ mandate_id: string; canonical: string; digest: string }>;
          return rows.map(mandateEventRowOf);
        },
        async expireMandate(expiry: MandateExpireStore): Promise<void> {
          db.transaction(() => {
            const plan = planMandateExpiry(expiry, sqliteSnapshot(db, { options: {} }, [expiry.mandateId]));
            sqliteApply(db, plan);
          }).immediate();
        },
        async listMandates(filter?: MandateListFilter): Promise<MandateListPage> {
          return sqliteListMandates(db, filter);
        },
      };
    },
  },
  postgres: {
    async migrate(client) {
      await client.query(POSTGRES_MANDATES_DDL);
    },
    async lock(client, write) {
      for (const id of mandateIdsOf(write)) await client.query(PG.lock, [id]);
    },
    async beforeInsert(client, write) {
      const plan = planMandateWrite(write, await postgresSnapshot(client, write, mandateIdsOf(write)));
      if (plan) await postgresApply(client, plan);
    },
    methods({ pool, inTransaction }) {
      return {
        async getMandate(mandateId: string): Promise<MandateRow | null> {
          const row = (await pool.query<MandateDbRow>(PG.selectByIdOrDigest, [mandateId])).rows[0];
          return row ? mandateRowOf(row) : null;
        },
        async getMandateTotals(mandateId: string): Promise<Record<string, number>> {
          const rows = (await pool.query<{ cap: string; total: string }>(PG.selectTotals, [mandateId])).rows;
          return Object.fromEntries(rows.map((r) => [r.cap, Number(r.total)]));
        },
        async listMandateEvents(mandateId: string): Promise<MandateEventRow[]> {
          const rows = (await pool.query<{ mandate_id: string; canonical: string; digest: string }>(PG.selectEvents, [mandateId])).rows;
          return rows.map(mandateEventRowOf);
        },
        async expireMandate(expiry: MandateExpireStore): Promise<void> {
          await inTransaction(async (client) => {
            const plan = planMandateExpiry(expiry, await postgresSnapshot(client, { options: {} }, [expiry.mandateId]));
            await postgresApply(client, plan);
          });
        },
        async listMandates(filter?: MandateListFilter): Promise<MandateListPage> {
          return postgresListMandates(pool, filter);
        },
      };
    },
  },
  memory: {
    createState(): MemoryMandatesState {
      return { rows: new Map(), byDigest: new Map(), totals: new Map(), events: new Map() };
    },
    check(state: MemoryMandatesState, write) {
      memoryPlan(state, write);
    },
    apply(state: MemoryMandatesState, write) {
      const plan = memoryPlan(state, write);
      if (plan) memoryApply(state, plan);
    },
    methods(state: MemoryMandatesState) {
      const byIdOrDigest = (key: string): MandateRow | undefined => state.rows.get(key) ?? state.rows.get(state.byDigest.get(key) ?? '');
      return {
        async getMandate(mandateId: string): Promise<MandateRow | null> {
          const row = byIdOrDigest(mandateId);
          return row ? { ...row } : null;
        },
        async getMandateTotals(mandateId: string): Promise<Record<string, number>> {
          const totals = state.totals.get(mandateId);
          return totals ? Object.fromEntries([...totals.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([cap, t]) => [cap, t.total])) : {};
        },
        async listMandateEvents(mandateId: string): Promise<MandateEventRow[]> {
          return (state.events.get(mandateId) ?? []).map((e) => ({ ...e, body: JSON.parse(e.canonical) }));
        },
        async expireMandate(expiry: MandateExpireStore): Promise<void> {
          memoryApply(state, planMandateExpiry(expiry, memorySnapshot(state, { options: {} }, [expiry.mandateId])));
        },
        async listMandates(filter?: MandateListFilter): Promise<MandateListPage> {
          return memoryListMandates(state, filter);
        },
      };
    },
  },
};
