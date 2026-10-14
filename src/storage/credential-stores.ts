/**
 * Durable credential stores — the registration record kept beside the evidence.
 *
 * A record whose signature nothing can check is not evidence of a signature;
 * it is a claim that one existed. Keys held in a `Map` die with the process
 * while the chain they signed lives on in SQLite or Postgres. These three
 * backends put the keys in the same store as the records so the two are
 * backed up together, restored together, and exported together.
 *
 * SHAPE: an append-only event log, not a mutable credential row.
 *
 *   credential_events   — one immutable row per fact. Registration is a row.
 *                         Revocation is a row. A counter regression is a row.
 *                         UPDATE and DELETE are refused by triggers on both
 *                         SQL backends and in code on all three.
 *   credential_counters — the one genuinely mutable thing: the WebAuthn
 *                         signature counter, which changes on every assertion.
 *                         It is an anti-replay high-water mark, not evidence,
 *                         so it is a small mutable table rather than a row per
 *                         signature.
 *
 * The event log is the point. A mutable `status` column answers only "is this
 * key good now", and the question an auditor asks is "was it good on the 4th
 * of March, when it signed this". A log answers that, and — crucially — it
 * answers it with rows that carry their own timestamps, which is the first
 * half of anchoring registration into the evidence chain itself (see
 * `docs/design/credential-store.md`).
 *
 * The state derivation lives in ONE place for all three backends:
 * `foldCredentialEvents()` in `src/attestation/credential-store.ts`. That is
 * deliberate: storage adapters that each compute their own answers drift
 * apart, and the conformance suite holds all three to the one fold.
 */

import Database from 'better-sqlite3';
import { randomUUID } from 'crypto';
import type { Pool } from 'pg';
import { StorageAdapter } from '@tzun/engine';
import { EXISTING_ROW_TAG, postgresBackdatedIdGuard } from './append-only';
import {
  AsyncCredentialStore,
  CredentialAlgorithm,
  CredentialAlreadyRegisteredError,
  CredentialEvent,
  CredentialNotFoundError,
  CredentialSnapshot,
  CredentialStore,
  RevocationOptions,
  StoredCredential,
  assertCredentialInstant,
  foldCredentialEvents,
} from '../attestation/credential-store';

// ── schema ────────────────────────────────────────────────────────────────

/**
 * SQLite DDL, executed from `SqliteStorageAdapter.createTables()`.
 *
 * `seq INTEGER PRIMARY KEY AUTOINCREMENT` rather than a timestamp sort key:
 * two events written in the same millisecond must still fold in the order
 * they were written, and `datetime('now')` in SQLite has second resolution.
 * `event_id` carries the stable identity a row is referenced by.
 *
 * The triggers are what make "append-only" a property of the database rather
 * than a promise in a comment: no event is updated, deleted, replaced by an
 * insert over its seq or event_id, or written ahead of the events it follows.
 * They stop the application, a migration script and anyone at a `sqlite3`
 * prompt alike; they do not stop someone who drops the triggers first, which
 * is why the durable answer to a hostile operator is anchoring, not
 * permissions. Every trigger is `CREATE TRIGGER IF NOT EXISTS` under its own
 * name, so a store written before one existed gets it the next time it is
 * opened, and an existing trigger's body is never changed in place.
 */
export const CREDENTIAL_SCHEMA_SQLITE = `
  CREATE TABLE IF NOT EXISTS credential_events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL UNIQUE,
    credential_id TEXT NOT NULL,
    event_type    TEXT NOT NULL CHECK (event_type IN ('registered','revoked','counter_regressed')),
    occurred_at   TEXT NOT NULL,
    recorded_at   TEXT NOT NULL,
    user_id       TEXT,
    public_key    TEXT,
    algorithm     TEXT,
    reason        TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_credential_events_cred ON credential_events(credential_id);
  CREATE INDEX IF NOT EXISTS idx_credential_events_user ON credential_events(user_id);

  CREATE TABLE IF NOT EXISTS credential_counters (
    credential_id TEXT PRIMARY KEY,
    counter       INTEGER NOT NULL,
    updated_at    TEXT NOT NULL
  );

  CREATE TRIGGER IF NOT EXISTS credential_events_block_update
  BEFORE UPDATE ON credential_events
  BEGIN
    SELECT RAISE(ABORT, 'credential_events is append-only (a registration record cannot be rewritten)');
  END;

  CREATE TRIGGER IF NOT EXISTS credential_events_block_delete
  BEFORE DELETE ON credential_events
  BEGIN
    SELECT RAISE(ABORT, 'credential_events rows cannot be deleted (credentials are revoked, never removed)');
  END;

  -- No insert over an existing event. REPLACE conflict
  -- resolution (INSERT OR REPLACE, REPLACE INTO) deletes the row an insert
  -- conflicts with and fires neither trigger above, so without this guard
  -- REPLACE would put another public key on a registration or rewrite a
  -- revocation. A BEFORE INSERT trigger runs before conflict handling, so an
  -- insert naming a seq or an event_id a row holds is refused whatever its
  -- conflict clause, as envelopes_block_replace refuses one in sqlite.ts. An
  -- insert that names no seq reads NEW.seq as -1 here, and
  -- credential_events_block_negative_rowid refuses a row written at a
  -- negative seq, so no row holds -1.
  CREATE TRIGGER IF NOT EXISTS credential_events_block_replace
  BEFORE INSERT ON credential_events
  BEGIN
    SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} credential_events rows are append-only (INSERT over an existing row refused)')
     WHERE EXISTS (SELECT 1 FROM credential_events WHERE seq = NEW.seq)
        OR EXISTS (SELECT 1 FROM credential_events WHERE event_id = NEW.event_id);
  END;

  CREATE TRIGGER IF NOT EXISTS credential_events_block_negative_rowid
  AFTER INSERT ON credential_events
  BEGIN
    SELECT RAISE(ABORT, 'credential_events: a rowid cannot be negative')
     WHERE NEW.seq < 0;
  END;

  -- A seq written explicitly is above every seq the log holds. Events fold in
  -- seq order and a credential's first registration is the one that counts,
  -- so a registration written below the last would put another key on the
  -- credential without replacing a row. An insert that names no seq reads
  -- NEW.seq as -1 here and gets the next one; a seq a row holds is left to
  -- credential_events_block_replace, which reports it as the duplicate it is.
  CREATE TRIGGER IF NOT EXISTS credential_events_block_backdated_seq
  BEFORE INSERT ON credential_events
  BEGIN
    SELECT RAISE(ABORT, 'credential_events: an explicit seq must be above every existing seq')
     WHERE NEW.seq <> -1
       AND NEW.seq < (SELECT MAX(seq) FROM credential_events)
       AND NOT EXISTS (SELECT 1 FROM credential_events WHERE seq = NEW.seq);
  END;
`;

/** Postgres DDL, executed from `PostgresStorageAdapter.ensureTables()`. */
export const CREDENTIAL_SCHEMA_POSTGRES = `
  CREATE TABLE IF NOT EXISTS credential_events (
    seq           BIGSERIAL PRIMARY KEY,
    event_id      TEXT NOT NULL UNIQUE,
    credential_id TEXT NOT NULL,
    event_type    TEXT NOT NULL CHECK (event_type IN ('registered','revoked','counter_regressed')),
    occurred_at   TIMESTAMPTZ NOT NULL,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id       TEXT,
    public_key    TEXT,
    algorithm     TEXT,
    reason        TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_credential_events_cred ON credential_events(credential_id);
  CREATE INDEX IF NOT EXISTS idx_credential_events_user ON credential_events(user_id);

  CREATE TABLE IF NOT EXISTS credential_counters (
    credential_id TEXT PRIMARY KEY,
    counter       BIGINT NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL
  );
`;

/**
 * Postgres append-only enforcement, written with CREATE OR REPLACE so
 * re-running `ensureTables()` is safe. Same shape as the `envelopes` and
 * `model_descriptors` guards above it in that file, and with the same honest
 * scope: it stops a least-privileged DML role, not the table owner. Each
 * function runs with its search_path pinned to `pg_catalog, pg_temp`, as every
 * SDK function does.
 *
 * No event is written ahead of the events it follows: events
 * fold in seq order and a credential's first registration is the one that
 * counts, so a registration planted at seq 0 would put another key on the
 * credential with one plain INSERT. `credential_events_block_backdated_seq`
 * refuses a seq the sequence did not hand the insert, or one below a seq
 * already committed, and gives every event a seq drawn as it is written
 * (`postgresBackdatedIdGuard`). The store's own writes name no seq.
 */
export const CREDENTIAL_TRIGGERS_POSTGRES = `
  CREATE OR REPLACE FUNCTION credential_events_block_mutation()
  RETURNS TRIGGER AS $$
  BEGIN
    RAISE EXCEPTION 'credential_events rows are append-only (% refused)', TG_OP;
  END;
  $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

  DROP TRIGGER IF EXISTS credential_events_block_mutation_trigger ON credential_events;
  CREATE TRIGGER credential_events_block_mutation_trigger
    BEFORE UPDATE OR DELETE ON credential_events
    FOR EACH ROW EXECUTE FUNCTION credential_events_block_mutation();

  DROP TRIGGER IF EXISTS credential_events_block_truncate_trigger ON credential_events;
  CREATE TRIGGER credential_events_block_truncate_trigger
    BEFORE TRUNCATE ON credential_events
    FOR EACH STATEMENT EXECUTE FUNCTION credential_events_block_mutation();

  ${postgresBackdatedIdGuard('credential_events_block_backdated_seq', 'credential_events', 'seq')}

  DROP TRIGGER IF EXISTS credential_events_block_backdated_seq_trigger ON credential_events;
  CREATE TRIGGER credential_events_block_backdated_seq_trigger
    BEFORE INSERT ON credential_events
    FOR EACH ROW EXECUTE FUNCTION credential_events_block_backdated_seq();
`;

// ── shared helpers ────────────────────────────────────────────────────────

/**
 * Build the one immutable event a registration writes.
 *
 * A registration whose `registeredAt` the caller supplied keeps that instant:
 * the caller knows when the ceremony happened, the store only knows when it
 * heard about it. Both are recorded — `occurred_at` and `recorded_at` — because
 * the gap between them is itself something an auditor may need to see.
 */
function registrationEvent(credential: StoredCredential, now: string): CredentialEvent {
  assertCredentialInstant('registeredAt', credential.registeredAt);
  return {
    eventId: randomUUID(),
    credentialId: credential.credentialId,
    type: 'registered',
    occurredAt: credential.registeredAt,
    recordedAt: now,
    userId: credential.userId,
    publicKey: credential.publicKey,
    algorithm: credential.algorithm,
  };
}

/**
 * Build the one immutable event a revocation writes.
 *
 * `occurredAt` is the caller's instant when they gave one: a key reported
 * stolen on the 3rd but processed on the 9th was not trustworthy on the 4th.
 */
function revocationEvent(credentialId: string, options: RevocationOptions): CredentialEvent {
  if (options.revokedAt !== undefined) assertCredentialInstant('revokedAt', options.revokedAt);
  const now = new Date().toISOString();
  const ev: CredentialEvent = {
    eventId: randomUUID(),
    credentialId,
    type: 'revoked',
    occurredAt: options.revokedAt ?? now,
    recordedAt: now,
  };
  if (options.reason !== undefined) ev.reason = options.reason;
  return ev;
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

/** Rows -> events, with pg's Date columns normalised to the ISO strings the
 * memory and SQLite backends return. */
type EventRow = {
  event_id: string;
  credential_id: string;
  event_type: CredentialEvent['type'];
  occurred_at: unknown;
  recorded_at: unknown;
  user_id: string | null;
  public_key: string | null;
  algorithm: string | null;
  reason: string | null;
};

function rowToEvent(row: EventRow): CredentialEvent {
  const ev: CredentialEvent = {
    eventId: row.event_id,
    credentialId: row.credential_id,
    type: row.event_type,
    occurredAt: toIso(row.occurred_at),
    recordedAt: toIso(row.recorded_at),
  };
  if (row.user_id !== null) ev.userId = row.user_id;
  if (row.public_key !== null) ev.publicKey = row.public_key;
  if (row.algorithm !== null) ev.algorithm = row.algorithm as CredentialAlgorithm;
  if (row.reason !== null) ev.reason = row.reason;
  return ev;
}

/** The single `snapshot()` implementation every backend shares. */
async function snapshotFrom(
  store: AsyncCredentialStore,
  credentialIds?: readonly string[]
): Promise<CredentialStore> {
  if (credentialIds === undefined) {
    return new CredentialSnapshot(await store.list());
  }
  const out: StoredCredential[] = [];
  for (const id of credentialIds) {
    const cred = await store.getByCredentialId(id);
    if (cred) out.push(cred);
  }
  return new CredentialSnapshot(out);
}

// ── memory ────────────────────────────────────────────────────────────────

/**
 * In-memory durable-store double.
 *
 * Faithful to the SQL backends in the way the memory StorageAdapter is meant
 * to be: it holds the same append-only event array, folds it with the same
 * function, throws the same errors, and returns detached copies. It is a
 * double, not a store — everything is lost when the process exits.
 */
export class MemoryCredentialStore implements AsyncCredentialStore {
  private events: CredentialEvent[] = [];
  private counters = new Map<string, number>();

  private state(): StoredCredential[] {
    return foldCredentialEvents(this.events, this.counters);
  }

  private find(credentialId: string): StoredCredential | undefined {
    return this.state().find((c) => c.credentialId === credentialId);
  }

  async register(credential: StoredCredential): Promise<void> {
    if (this.find(credential.credentialId)) {
      throw new CredentialAlreadyRegisteredError(credential.credentialId);
    }
    this.events.push(registrationEvent(credential, new Date().toISOString()));
    if (credential.counter > 0) this.counters.set(credential.credentialId, credential.counter);
  }

  async getByCredentialId(credentialId: string): Promise<StoredCredential | undefined> {
    return this.find(credentialId);
  }

  async getByUserId(userId: string): Promise<StoredCredential[]> {
    return this.state().filter((c) => c.userId === userId);
  }

  async revoke(credentialId: string, options: RevocationOptions = {}): Promise<void> {
    const cred = this.find(credentialId);
    if (!cred) throw new CredentialNotFoundError(credentialId);
    if (cred.revokedAt !== undefined) return;
    const ev = revocationEvent(credentialId, options);
    this.events.push(ev);
  }

  async updateCounter(credentialId: string, newCounter: number): Promise<void> {
    const cred = this.find(credentialId);
    if (!cred) throw new CredentialNotFoundError(credentialId);
    if (newCounter < cred.counter) {
      const now = new Date().toISOString();
      this.events.push({
        eventId: randomUUID(),
        credentialId,
        type: 'counter_regressed',
        occurredAt: now,
        recordedAt: now,
      });
      return;
    }
    this.counters.set(credentialId, newCounter);
  }

  async list(): Promise<StoredCredential[]> {
    return this.state();
  }

  async history(credentialId?: string): Promise<CredentialEvent[]> {
    const all = this.events.map((e) => ({ ...e }));
    return credentialId === undefined ? all : all.filter((e) => e.credentialId === credentialId);
  }

  async snapshot(credentialIds?: readonly string[]): Promise<CredentialStore> {
    return snapshotFrom(this, credentialIds);
  }
}

// ── SQLite ────────────────────────────────────────────────────────────────

/**
 * SQLite-backed credential store, sharing the `Database` handle — and
 * therefore the file, the WAL and the 0600 permissions — of the
 * `SqliteStorageAdapter` that owns the evidence. One file to back up, one file
 * to restore, one file to move to a new host without losing every passkey.
 */
export class SqliteCredentialStore implements AsyncCredentialStore {
  constructor(private readonly db: Database.Database) {}

  private events(credentialId?: string): CredentialEvent[] {
    const rows = (
      credentialId === undefined
        ? this.db
            .prepare(
              'SELECT event_id, credential_id, event_type, occurred_at, recorded_at, user_id, public_key, algorithm, reason FROM credential_events ORDER BY seq ASC'
            )
            .all()
        : this.db
            .prepare(
              'SELECT event_id, credential_id, event_type, occurred_at, recorded_at, user_id, public_key, algorithm, reason FROM credential_events WHERE credential_id = ? ORDER BY seq ASC'
            )
            .all(credentialId)
    ) as EventRow[];
    return rows.map(rowToEvent);
  }

  private counters(): Map<string, number> {
    const rows = this.db
      .prepare('SELECT credential_id, counter FROM credential_counters')
      .all() as Array<{ credential_id: string; counter: number }>;
    return new Map(rows.map((r) => [r.credential_id, r.counter]));
  }

  private state(): StoredCredential[] {
    return foldCredentialEvents(this.events(), this.counters());
  }

  private insert(ev: CredentialEvent): void {
    this.db
      .prepare(
        `INSERT INTO credential_events
           (event_id, credential_id, event_type, occurred_at, recorded_at, user_id, public_key, algorithm, reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        ev.eventId,
        ev.credentialId,
        ev.type,
        ev.occurredAt,
        ev.recordedAt,
        ev.userId ?? null,
        ev.publicKey ?? null,
        ev.algorithm ?? null,
        ev.reason ?? null
      );
  }

  async register(credential: StoredCredential): Promise<void> {
    if (this.state().some((c) => c.credentialId === credential.credentialId)) {
      throw new CredentialAlreadyRegisteredError(credential.credentialId);
    }
    this.insert(registrationEvent(credential, new Date().toISOString()));
    if (credential.counter > 0) {
      this.db
        .prepare(
          `INSERT INTO credential_counters (credential_id, counter, updated_at) VALUES (?, ?, ?)
           ON CONFLICT(credential_id) DO UPDATE SET counter = excluded.counter, updated_at = excluded.updated_at`
        )
        .run(credential.credentialId, credential.counter, new Date().toISOString());
    }
  }

  async getByCredentialId(credentialId: string): Promise<StoredCredential | undefined> {
    return this.state().find((c) => c.credentialId === credentialId);
  }

  async getByUserId(userId: string): Promise<StoredCredential[]> {
    return this.state().filter((c) => c.userId === userId);
  }

  async revoke(credentialId: string, options: RevocationOptions = {}): Promise<void> {
    const cred = await this.getByCredentialId(credentialId);
    if (!cred) throw new CredentialNotFoundError(credentialId);
    if (cred.revokedAt !== undefined) return;
    const ev = revocationEvent(credentialId, options);
    this.insert(ev);
  }

  async updateCounter(credentialId: string, newCounter: number): Promise<void> {
    const cred = await this.getByCredentialId(credentialId);
    if (!cred) throw new CredentialNotFoundError(credentialId);
    const now = new Date().toISOString();
    if (newCounter < cred.counter) {
      this.insert({
        eventId: randomUUID(),
        credentialId,
        type: 'counter_regressed',
        occurredAt: now,
        recordedAt: now,
      });
      return;
    }
    this.db
      .prepare(
        `INSERT INTO credential_counters (credential_id, counter, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(credential_id) DO UPDATE SET counter = excluded.counter, updated_at = excluded.updated_at`
      )
      .run(credentialId, newCounter, now);
  }

  async list(): Promise<StoredCredential[]> {
    return this.state();
  }

  async history(credentialId?: string): Promise<CredentialEvent[]> {
    return this.events(credentialId);
  }

  async snapshot(credentialIds?: readonly string[]): Promise<CredentialStore> {
    return snapshotFrom(this, credentialIds);
  }
}

// ── Postgres ──────────────────────────────────────────────────────────────

/**
 * Postgres-backed credential store, sharing the `Pool` of the
 * `PostgresStorageAdapter` that owns the evidence.
 */
export class PostgresCredentialStore implements AsyncCredentialStore {
  constructor(private readonly pool: Pool) {}

  private async events(credentialId?: string): Promise<CredentialEvent[]> {
    const sql =
      'SELECT event_id, credential_id, event_type, occurred_at, recorded_at, user_id, public_key, algorithm, reason FROM credential_events';
    const res =
      credentialId === undefined
        ? await this.pool.query(`${sql} ORDER BY seq ASC`)
        : await this.pool.query(`${sql} WHERE credential_id = $1 ORDER BY seq ASC`, [credentialId]);
    return (res.rows as EventRow[]).map(rowToEvent);
  }

  private async counters(): Promise<Map<string, number>> {
    const res = await this.pool.query('SELECT credential_id, counter FROM credential_counters');
    return new Map(
      (res.rows as Array<{ credential_id: string; counter: string | number }>).map((r) => [
        r.credential_id,
        Number(r.counter),
      ])
    );
  }

  private async state(): Promise<StoredCredential[]> {
    return foldCredentialEvents(await this.events(), await this.counters());
  }

  private async insert(ev: CredentialEvent): Promise<void> {
    await this.pool.query(
      `INSERT INTO credential_events
         (event_id, credential_id, event_type, occurred_at, recorded_at, user_id, public_key, algorithm, reason)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        ev.eventId,
        ev.credentialId,
        ev.type,
        ev.occurredAt,
        ev.recordedAt,
        ev.userId ?? null,
        ev.publicKey ?? null,
        ev.algorithm ?? null,
        ev.reason ?? null,
      ]
    );
  }

  async register(credential: StoredCredential): Promise<void> {
    const existing = await this.getByCredentialId(credential.credentialId);
    if (existing) throw new CredentialAlreadyRegisteredError(credential.credentialId);
    await this.insert(registrationEvent(credential, new Date().toISOString()));
    if (credential.counter > 0) {
      await this.pool.query(
        `INSERT INTO credential_counters (credential_id, counter, updated_at) VALUES ($1, $2, $3)
         ON CONFLICT (credential_id) DO UPDATE SET counter = EXCLUDED.counter, updated_at = EXCLUDED.updated_at`,
        [credential.credentialId, credential.counter, new Date().toISOString()]
      );
    }
  }

  async getByCredentialId(credentialId: string): Promise<StoredCredential | undefined> {
    return (await this.state()).find((c) => c.credentialId === credentialId);
  }

  async getByUserId(userId: string): Promise<StoredCredential[]> {
    return (await this.state()).filter((c) => c.userId === userId);
  }

  async revoke(credentialId: string, options: RevocationOptions = {}): Promise<void> {
    const cred = await this.getByCredentialId(credentialId);
    if (!cred) throw new CredentialNotFoundError(credentialId);
    if (cred.revokedAt !== undefined) return;
    const ev = revocationEvent(credentialId, options);
    await this.insert(ev);
  }

  async updateCounter(credentialId: string, newCounter: number): Promise<void> {
    const cred = await this.getByCredentialId(credentialId);
    if (!cred) throw new CredentialNotFoundError(credentialId);
    const now = new Date().toISOString();
    if (newCounter < cred.counter) {
      await this.insert({
        eventId: randomUUID(),
        credentialId,
        type: 'counter_regressed',
        occurredAt: now,
        recordedAt: now,
      });
      return;
    }
    await this.pool.query(
      `INSERT INTO credential_counters (credential_id, counter, updated_at) VALUES ($1, $2, $3)
       ON CONFLICT (credential_id) DO UPDATE SET counter = EXCLUDED.counter, updated_at = EXCLUDED.updated_at`,
      [credentialId, newCounter, now]
    );
  }

  async list(): Promise<StoredCredential[]> {
    return this.state();
  }

  async history(credentialId?: string): Promise<CredentialEvent[]> {
    return this.events(credentialId);
  }

  async snapshot(credentialIds?: readonly string[]): Promise<CredentialStore> {
    return snapshotFrom(this, credentialIds);
  }
}

// ── discovery ─────────────────────────────────────────────────────────────

/**
 * A storage adapter that can also hold credentials.
 *
 * Deliberately NOT folded into `StorageAdapter`. The cloud `HttpStorageAdapter`
 * holds no credentials: the cloud transport neither stores nor reads them, so
 * on it the registered keys stay with the relying party that ran the WebAuthn
 * ceremony. Widening the main interface would force it (and
 * `VerifyingStorageProxy`, and every future adapter) to grow a method that
 * throws. An optional capability interface says what is true: some stores
 * have a credential directory, some do not, and the caller can find out.
 */
export interface CredentialStoreProvider {
  credentialStore(): AsyncCredentialStore;
}

/**
 * The durable credential directory belonging to this storage adapter, or
 * `undefined` when the adapter has none.
 *
 * `undefined` is a real answer and callers must keep handling it: it is what
 * keeps `verifyAttestation()` reporting `signatureValid: null` /
 * `no_credential_store` — "nobody can check this" — instead of inventing a
 * verdict. Cloud mode and any third-party adapter land here.
 */
export function credentialStoreFor(storage: StorageAdapter): AsyncCredentialStore | undefined {
  const candidate = storage as Partial<CredentialStoreProvider>;
  if (typeof candidate.credentialStore !== 'function') return undefined;
  return candidate.credentialStore();
}
