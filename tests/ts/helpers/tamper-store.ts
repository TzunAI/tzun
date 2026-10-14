/**
 * Tamper with a STORED evidence envelope the way an attacker with write access
 * to the store would — behind the adapter's back, not through it.
 *
 * Every adapter, the memory one included, clones on every read and write, so
 * assigning to what `retrieve()` returned changes a detached copy and the
 * store does not move. A tamper test has to rewrite the row itself, which is
 * what an attacker with write access does and what this helper does on each
 * backend; a test that only edits its own copy would detect nothing in
 * production.
 *
 * Per backend:
 *   - memory   — the private Map entry is mutated in place (heap access).
 *   - sqlite   — `UPDATE envelopes SET envelope = ?` on the open handle, with
 *                the `envelopes` triggers lifted around it
 *                (`withSqliteEnvelopeTriggersLifted`), the explicit bypass the
 *                SQLite append-only triggers require.
 *   - postgres — the same UPDATE under `session_replication_role = 'replica'`,
 *                the explicit bypass the Postgres append-only triggers require.
 *
 * A `VerifyingStorageProxy` is unwrapped, so callers can pass the proxy or
 * the adapter behind it (`Tzun.getStorage()`).
 *
 * Returns a detached copy of the row as it now stands.
 */
import type { EvidenceEnvelope, StorageAdapter } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../../src/storage/memory';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';

/**
 * Run `edit` on a SQLite handle with every trigger on `envelopes` lifted — what
 * an insider with the file open has to do: drop the triggers, make
 * the edit, put them back. One transaction, so no other connection sees the
 * table unguarded. The SQLite counterpart of the Postgres branch's
 * `session_replication_role = 'replica'`.
 */
export function withSqliteEnvelopeTriggersLifted<T>(db: import('better-sqlite3').Database, edit: () => T): T {
  return db.transaction(() => {
    const triggers = db
      .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'envelopes'")
      .all() as Array<{ name: string; sql: string }>;
    for (const t of triggers) db.exec(`DROP TRIGGER "${t.name}"`);
    const result = edit();
    for (const t of triggers) db.exec(t.sql);
    return result;
  })();
}

function unwrap(storage: StorageAdapter): StorageAdapter {
  let s: unknown = storage;
  while (s && typeof s === 'object' && 'inner' in (s as Record<string, unknown>)) {
    s = (s as { inner: unknown }).inner;
  }
  return s as StorageAdapter;
}

export async function rewriteStoredEnvelope(
  storage: StorageAdapter,
  evidenceId: string,
  mutate: (envelope: EvidenceEnvelope) => void,
): Promise<EvidenceEnvelope> {
  const adapter = unwrap(storage);

  if (adapter instanceof MemoryStorageAdapter) {
    const rows = (adapter as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes;
    const row = rows.get(evidenceId);
    if (!row) throw new Error(`rewriteStoredEnvelope: no stored envelope "${evidenceId}"`);
    mutate(row);
    return JSON.parse(JSON.stringify(row)) as EvidenceEnvelope;
  }

  if (adapter instanceof SqliteStorageAdapter) {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    const row = db.prepare('SELECT envelope FROM envelopes WHERE evidence_id = ?').get(evidenceId) as
      | { envelope: string }
      | undefined;
    if (!row) throw new Error(`rewriteStoredEnvelope: no stored envelope "${evidenceId}"`);
    const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
    mutate(envelope);
    withSqliteEnvelopeTriggersLifted(db, () =>
      db.prepare('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?').run(JSON.stringify(envelope), evidenceId),
    );
    return envelope;
  }

  if (adapter instanceof PostgresStorageAdapter) {
    const pool = (adapter as unknown as { pool: import('pg').Pool }).pool;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL session_replication_role = 'replica'");
      const sel = await client.query('SELECT envelope FROM envelopes WHERE evidence_id = $1 FOR UPDATE', [evidenceId]);
      if (sel.rows.length === 0) throw new Error(`rewriteStoredEnvelope: no stored envelope "${evidenceId}"`);
      const raw = sel.rows[0].envelope;
      const envelope = (typeof raw === 'string' ? JSON.parse(raw) : raw) as EvidenceEnvelope;
      mutate(envelope);
      await client.query('UPDATE envelopes SET envelope = $1 WHERE evidence_id = $2', [JSON.stringify(envelope), evidenceId]);
      await client.query('COMMIT');
      return envelope;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => { /* ignore */ });
      throw err;
    } finally {
      client.release();
    }
  }

  throw new Error(`rewriteStoredEnvelope: unsupported adapter ${adapter?.constructor?.name ?? typeof adapter}`);
}

/**
 * Delete a STORED evidence row the way an insider with write access would —
 * behind the adapter's back, and through the explicit bypass each backend's
 * append-only guards require, exactly as `rewriteStoredEnvelope` does.
 *
 * What it is for: a deleted record is the one tamper the records themselves
 * cannot show. Nothing survives to be recomputed, so the only trace is the
 * chain's recorded high-water mark — which is why that mark is kept per chain
 * and does not fall with the rows, and why a chain whose every
 * record is deleted reads differently from one that was always empty.
 *
 * `deleteEnvelopeForDemo` is NOT used here: it is gated behind
 * `demoTamperHooks` and writes a sentinel row saying a demo did it. An insider
 * leaves neither.
 */
export async function deleteStoredEnvelope(
  storage: StorageAdapter,
  evidenceId: string,
): Promise<void> {
  const adapter = unwrap(storage);

  if (adapter instanceof MemoryStorageAdapter) {
    const rows = (adapter as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes;
    if (!rows.delete(evidenceId)) {
      throw new Error(`deleteStoredEnvelope: no stored envelope "${evidenceId}"`);
    }
    return;
  }

  if (adapter instanceof SqliteStorageAdapter) {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    const deleted = withSqliteEnvelopeTriggersLifted(db, () =>
      db.prepare('DELETE FROM envelopes WHERE evidence_id = ?').run(evidenceId),
    );
    if (deleted.changes === 0) {
      throw new Error(`deleteStoredEnvelope: no stored envelope "${evidenceId}"`);
    }
    return;
  }

  if (adapter instanceof PostgresStorageAdapter) {
    const pool = (adapter as unknown as { pool: import('pg').Pool }).pool;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL session_replication_role = 'replica'");
      const res = await client.query('DELETE FROM envelopes WHERE evidence_id = $1', [evidenceId]);
      if (res.rowCount === 0) {
        throw new Error(`deleteStoredEnvelope: no stored envelope "${evidenceId}"`);
      }
      await client.query('COMMIT');
      return;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => { /* ignore */ });
      throw err;
    } finally {
      client.release();
    }
  }

  throw new Error(`deleteStoredEnvelope: unsupported adapter ${adapter?.constructor?.name ?? typeof adapter}`);
}
