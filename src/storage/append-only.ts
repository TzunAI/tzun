/**
 * Append-only refusals, stated once for every backend.
 *
 * Six write methods — `storeChain`, `storeAnnotation`, `storeRelink`,
 * `storeFork`, `appendModelDescriptorAnnotation` (duplicate id) and
 * `appendModelDescriptorAnnotation` (unknown descriptor digest) — are a bare
 * `INSERT` against a primary key or a foreign key on SQLite and Postgres. The
 * memory adapter refuses the same writes rather than upserting: a second
 * `storeChain` for an existing chain id must not replace the chain identity —
 * its status, `sealedAt`, `parentChainId`, `forkPoint` — in dev while it
 * throws in production, and an annotation for a descriptor that was never
 * registered is refused by every store.
 *
 * Where the adapters raise their OWN errors (`store()` duplicate,
 * `storeIncident()` duplicate, the not-found cases) they are byte-identical in
 * class and message on all three backends. A driver's own error differs by
 * backend — `SqliteError` vs pg's `DatabaseError` with `code: '23505'` — so a
 * `catch` written against one backend would be dead code on the next. These
 * two classes are what every adapter throws for the two conditions, with the
 * driver error kept as `cause`.
 */

/** A write to an append-only table named a key that already exists. */
export class DuplicateRecordError extends Error {
  readonly code = 'duplicate_record' as const;

  constructor(
    /** What kind of record: 'Chain', 'Annotation', 'Relink', 'Fork', 'Model descriptor annotation'. */
    public readonly recordType: string,
    /** The primary key that already exists. */
    public readonly recordId: string,
    options?: { cause?: unknown },
  ) {
    super(`${recordType} "${recordId}" already exists. Storage is append-only.`);
    this.name = 'DuplicateRecordError';
    if (options?.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    Object.setPrototypeOf(this, DuplicateRecordError.prototype);
  }
}

/** A write referenced a parent row that does not exist. */
export class MissingReferenceError extends Error {
  readonly code = 'missing_reference' as const;

  constructor(
    /** What kind of record was being written. */
    public readonly recordType: string,
    /** What it referenced that is not there. */
    public readonly referenceType: string,
    public readonly referenceId: string,
    options?: { cause?: unknown },
  ) {
    super(`${recordType} references ${referenceType} "${referenceId}", which does not exist.`);
    this.name = 'MissingReferenceError';
    if (options?.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    Object.setPrototypeOf(this, MissingReferenceError.prototype);
  }
}

/**
 * The shape of a driver error the SQL adapters translate. better-sqlite3 sets
 * `code` to `SQLITE_CONSTRAINT_PRIMARYKEY` / `SQLITE_CONSTRAINT_UNIQUE` /
 * `SQLITE_CONSTRAINT_FOREIGNKEY`; pg sets the SQLSTATE `23505`
 * (unique_violation) / `23503` (foreign_key_violation).
 */
type DriverError = { code?: unknown; message?: unknown };

const DUPLICATE_CODES = new Set(['SQLITE_CONSTRAINT_PRIMARYKEY', 'SQLITE_CONSTRAINT_UNIQUE', '23505']);
const MISSING_REFERENCE_CODES = new Set(['SQLITE_CONSTRAINT_FOREIGNKEY', '23503']);

/**
 * The tag the SQLite adapter's `*_block_replace` guards put in
 * their refusal: an insert named a key a row of an append-only table already
 * holds. The guard runs before the key's own constraint, so on SQLite this,
 * with the code `SQLITE_CONSTRAINT_TRIGGER`, is what a duplicate key is
 * refused with, and it is translated as one.
 */
export const EXISTING_ROW_TAG = '[tzun:duplicate_record]';

/** True when `err` is a `*_block_replace` guard's refusal. */
function isExistingRowRefusal(err: unknown): boolean {
  // Read the message without `instanceof Error`: a driver error can come from
  // another realm (a native module loaded once for several VM contexts).
  const message = (err as DriverError | null)?.message;
  return typeof message === 'string' && message.includes(EXISTING_ROW_TAG);
}

/**
 * Turn a driver constraint error into the SDK's own, or return it unchanged
 * when it is something else (a syntax error, a lost connection — those must
 * surface as what they are).
 */
export function translateConstraintError(
  err: unknown,
  ctx: {
    recordType: string;
    recordId: string;
    /** Present when the write carries a foreign key that may be missing. */
    reference?: { type: string; id: string };
  },
): unknown {
  const code = (err as DriverError | null)?.code;
  if (typeof code !== 'string') return err;
  if (DUPLICATE_CODES.has(code) || isExistingRowRefusal(err)) {
    return new DuplicateRecordError(ctx.recordType, ctx.recordId, { cause: err });
  }
  if (MISSING_REFERENCE_CODES.has(code) && ctx.reference) {
    return new MissingReferenceError(ctx.recordType, ctx.reference.type, ctx.reference.id, { cause: err });
  }
  return err;
}

/**
 * The Postgres guard that keeps each row of a `BIGSERIAL`-keyed table after
 * every row committed before it, as `CREATE OR REPLACE
 * FUNCTION`. The SDK reads `credential_events`, `custody_entries`, `logs` and
 * `anchor_publications` in id order and never names an id when it writes one.
 * A `BIGSERIAL` column still takes an id written explicitly, so without this
 * a least-privileged INSERT role could put a row ahead of the rows it follows:
 * a registration at `seq` 0 puts another key on a credential, because the
 * first registration is the one that counts.
 *
 * The SQLite guards (`<table>_block_backdated_<id>`) refuse an explicit id
 * below the table's last, reading the last id when the trigger runs. Postgres
 * sequence values commit out of order, so the same read here would refuse an
 * id the sequence handed out: a writer that drew 5 and waited on a lock while
 * another drew 6 and committed would read 6. The guard instead refuses an
 * explicit id with two checks, then gives the row its id itself:
 *
 *   1. The id is not below any id visible to the INSERT. The function is
 *      STABLE, so its query reads the INSERT statement's snapshot, not a new
 *      one: every id visible there committed before that snapshot was taken,
 *      so it was drawn before the id the sequence hands the statement, which
 *      is therefore higher (BIGSERIAL's sequence has CACHE 1; with a larger
 *      cache each session draws from a block of its own, and this check
 *      refuses an insert whose block is below another session's committed
 *      ids).
 *   2. The id is the value the sequence last handed this session (`currval`).
 *      A default id always is. An id the session did not draw is refused,
 *      above the last included.
 *   3. The row takes a new value from the sequence. Drawn inside the guard,
 *      it is above every value drawn before the insert, so the row lands
 *      after every row committed before it, whatever the transaction's
 *      isolation level. Under REPEATABLE READ or SERIALIZABLE, check 1 reads
 *      the transaction's snapshot, so a value drawn early in the transaction
 *      and written once later rows have committed passes both checks; this is
 *      what keeps that row from landing ahead of them. Every insert takes two
 *      values from the sequence, so ids are sparse (a rolled-back insert
 *      leaves gaps too), and `RETURNING` gives the row's id. `nextval` changes
 *      the sequence, which a STABLE function is not meant to do; a trigger
 *      function is called once per row and never folded or cached, so the one
 *      effect of STABLE here is the snapshot check 1 reads.
 *
 * The inserting session's name resolution is not used. The table and its
 * sequence are found through the trigger's own table (`TG_TABLE_SCHEMA`,
 * `TG_TABLE_NAME`), and the function runs with `search_path` set to
 * `pg_catalog, pg_temp`, so a temporary table of the same name, or an
 * operator or `currval` on a schema the session puts ahead of `pg_catalog`,
 * cannot stand in for them.
 *
 * `name` is the function's name, the SQLite guard's, and `table` is the table
 * its messages name; the caller creates its trigger, BEFORE INSERT FOR EACH
 * ROW.
 */
export function postgresBackdatedIdGuard(name: string, table: string, column: string): string {
  return `
    CREATE OR REPLACE FUNCTION ${name}() RETURNS TRIGGER AS $$
    DECLARE
      v_table TEXT := format('%I.%I', TG_TABLE_SCHEMA, TG_TABLE_NAME);
      v_seq TEXT := pg_get_serial_sequence(v_table, '${column}');
      v_last BIGINT;
      v_drawn BIGINT;
    BEGIN
      EXECUTE format('SELECT MAX(%I) FROM %s', '${column}', v_table) INTO v_last;
      IF NEW.${column} < v_last THEN
        RAISE EXCEPTION '${table}: ${column} % is below the last ${column} (an explicit ${column} must be above every existing ${column})', NEW.${column};
      END IF;
      BEGIN
        v_drawn := currval(v_seq);
      EXCEPTION WHEN object_not_in_prerequisite_state THEN
        -- This session has drawn nothing from the sequence.
        v_drawn := NULL;
      END;
      IF NEW.${column} IS DISTINCT FROM v_drawn THEN
        RAISE EXCEPTION '${table}: ${column} % is not the one its sequence handed this insert (an explicit ${column} is refused)', NEW.${column};
      END IF;
      NEW.${column} := nextval(v_seq);
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp;
  `;
}
