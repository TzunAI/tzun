/**
 * Decider commitment openings (Record §6.3): the `decider_openings` table
 * and the store's commitment-salt secret, as a storage extension.
 *
 * A capture with `decider.commit: true` writes `cmt:<hex>` into the record
 * and keeps the opening, `{ salt, id }`, here, in the transaction that stores
 * the record (`StoreOptions.deciderOpening`). The table is outside the record
 * and unhashed; `getDeciderOpening(evidenceId)` reads it. Rows are
 * append-only. An opening that does not open the stored record's decider is
 * refused, so the table cannot hold an opening for a commitment it does not
 * open.
 *
 * The secret (`getDeciderCommitmentSecret`) is 32 random bytes minted the
 * first time it is read and kept for the life of the store. A capture under
 * an idempotency key derives its salt from it (`deciderCommitmentSalt`), so a
 * retry commits with the same salt; the secret never leaves the store.
 */
import { randomBytes } from 'crypto';
import { verifyDeciderOpening } from '@tzun/engine';
import type { DeciderOpening } from '@tzun/engine';
import type { StorageExtension, StoreWrite } from '../extensions';

/** Thrown when `StoreOptions.deciderOpening` does not open the record's `cmt:` decider. */
export class DeciderOpeningMismatchError extends Error {
  readonly code = 'decider_opening_mismatch' as const;
  constructor(evidenceId: string) {
    super(`The decider opening stored with record ${evidenceId} does not open its decider's commitment.`);
    this.name = 'DeciderOpeningMismatchError';
  }
}

/** The opening a write carries, after checking it opens the record's decider; `null` when the write carries none. */
function openingOf(write: StoreWrite): DeciderOpening | null {
  const opening = write.options.deciderOpening;
  if (opening === undefined || opening === null) return null;
  const decider = write.envelope.payload.decider;
  if (!decider || !verifyDeciderOpening(decider.id, opening)) {
    throw new DeciderOpeningMismatchError(write.envelope.payload.evidenceId);
  }
  return { salt: opening.salt, id: opening.id };
}

const SECRET_BYTES = 32;

export const SQLITE_DECIDERS_DDL = `
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
`;

export const POSTGRES_DECIDERS_DDL = `
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
`;

/** An opening already stored for the record must be the same opening; a second, different one is refused. */
function sameOpening(stored: { salt: string; inner_id: string }, opening: DeciderOpening): boolean {
  return stored.salt === opening.salt && stored.inner_id === opening.id;
}

interface MemoryDecidersState {
  openings: Map<string, DeciderOpening>;
  secret: Buffer;
}

/** The `decider_openings` table, the commitment-salt secret, and `getDeciderOpening`. */
export const decidersExtension: StorageExtension = {
  name: 'deciders',
  sqlite: {
    migrate(db) {
      db.exec(SQLITE_DECIDERS_DDL);
    },
    afterInsert(db, write) {
      const opening = openingOf(write);
      if (opening === null) return;
      const id = write.envelope.payload.evidenceId;
      const held = db.prepare('SELECT salt, inner_id FROM decider_openings WHERE evidence_id = ?').get(id) as
        | { salt: string; inner_id: string }
        | undefined;
      if (held) {
        if (!sameOpening(held, opening)) throw new DeciderOpeningMismatchError(id);
        return;
      }
      db.prepare('INSERT INTO decider_openings (evidence_id, salt, inner_id, created_at) VALUES (?, ?, ?, ?)').run(
        id,
        opening.salt,
        opening.id,
        new Date().toISOString(),
      );
    },
    methods(db) {
      return {
        async getDeciderOpening(evidenceId: string): Promise<DeciderOpening | null> {
          const row = db.prepare('SELECT salt, inner_id FROM decider_openings WHERE evidence_id = ?').get(evidenceId) as
            | { salt: string; inner_id: string }
            | undefined;
          return row ? { salt: row.salt, id: row.inner_id } : null;
        },
        async getDeciderCommitmentSecret(): Promise<Uint8Array> {
          const read = () =>
            db.prepare('SELECT secret FROM decider_commitment_secret WHERE id = 1').get() as { secret: string } | undefined;
          const minted = db
            .transaction(() => {
              const held = read();
              if (held) return held.secret;
              const secret = randomBytes(SECRET_BYTES).toString('base64');
              db.prepare('INSERT INTO decider_commitment_secret (id, secret) VALUES (1, ?)').run(secret);
              return secret;
            })
            .immediate();
          return new Uint8Array(Buffer.from(minted, 'base64'));
        },
      };
    },
  },
  postgres: {
    async migrate(client) {
      await client.query(POSTGRES_DECIDERS_DDL);
    },
    async afterInsert(client, write) {
      const opening = openingOf(write);
      if (opening === null) return;
      const id = write.envelope.payload.evidenceId;
      const held = await client.query<{ salt: string; inner_id: string }>(
        'SELECT salt, inner_id FROM decider_openings WHERE evidence_id = $1',
        [id],
      );
      if (held.rows[0]) {
        if (!sameOpening(held.rows[0], opening)) throw new DeciderOpeningMismatchError(id);
        return;
      }
      await client.query('INSERT INTO decider_openings (evidence_id, salt, inner_id) VALUES ($1, $2, $3)', [
        id,
        opening.salt,
        opening.id,
      ]);
    },
    methods({ pool }) {
      return {
        async getDeciderOpening(evidenceId: string): Promise<DeciderOpening | null> {
          const result = await pool.query<{ salt: string; inner_id: string }>(
            'SELECT salt, inner_id FROM decider_openings WHERE evidence_id = $1',
            [evidenceId],
          );
          const row = result.rows[0];
          return row ? { salt: row.salt, id: row.inner_id } : null;
        },
        async getDeciderCommitmentSecret(): Promise<Uint8Array> {
          // Insert-if-absent, then read: two openers racing both read the row
          // that won.
          await pool.query(
            'INSERT INTO decider_commitment_secret (id, secret) VALUES (1, $1) ON CONFLICT (id) DO NOTHING',
            [randomBytes(SECRET_BYTES).toString('base64')],
          );
          const result = await pool.query<{ secret: string }>('SELECT secret FROM decider_commitment_secret WHERE id = 1');
          return new Uint8Array(Buffer.from(result.rows[0].secret, 'base64'));
        },
      };
    },
  },
  memory: {
    createState(): MemoryDecidersState {
      return { openings: new Map(), secret: randomBytes(SECRET_BYTES) };
    },
    check(state: MemoryDecidersState, write) {
      const opening = openingOf(write);
      if (opening === null) return;
      const held = state.openings.get(write.envelope.payload.evidenceId);
      if (held && !(held.salt === opening.salt && held.id === opening.id)) {
        throw new DeciderOpeningMismatchError(write.envelope.payload.evidenceId);
      }
    },
    apply(state: MemoryDecidersState, write) {
      const opening = openingOf(write);
      if (opening === null) return;
      const id = write.envelope.payload.evidenceId;
      if (!state.openings.has(id)) state.openings.set(id, opening);
    },
    methods(state: MemoryDecidersState) {
      return {
        async getDeciderOpening(evidenceId: string): Promise<DeciderOpening | null> {
          const held = state.openings.get(evidenceId);
          return held ? { ...held } : null;
        },
        async getDeciderCommitmentSecret(): Promise<Uint8Array> {
          return new Uint8Array(state.secret);
        },
      };
    },
  },
};
