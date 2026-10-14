/**
 * The link index (`evidence_links`): the rows a stored record contributes,
 * the statements that read and write them on SQLite and Postgres, the memory
 * adapter's scan, and the page cursor.
 *
 * One row per well-formed link of a stored record: the record, the link's
 * index in its `links`, the relation, the target digest, and, for a
 * statement of a link record (one of its links other than `subject`), the
 * subject's digest. The rows are derived from the stored, hashed `links`
 * and written in the storing transaction; verification never reads them.
 * They exist so `tzun.links.to(digest)` and the decision-graph walk find the
 * records that name a digest a page at a time instead of scanning the store.
 *
 * A page is ordered by (`evidence_id`, `idx`), bytewise, and continues after
 * the last row of the page before it (`cursor`). A row whose record is no
 * longer in `envelopes` (the demo delete hook) is not returned.
 */
import type Database from 'better-sqlite3';
import type { Pool, PoolClient } from 'pg';
import {
  LINK_RECORD_AI_SYSTEM_ID,
  isRelationName,
  type EvidenceEnvelope,
  type EvidenceLinkRow,
} from '@tzun/engine';

/** The rows a page holds when the caller names no limit. */
export const LINK_INDEX_DEFAULT_LIMIT = 100;
/** The most rows one page holds. */
export const LINK_INDEX_MAX_LIMIT = 200;
/** The most relations one query may filter on. */
export const LINK_INDEX_MAX_RELS = 64;

const BARE_DIGEST_RE = /^[0-9a-f]{64}$/;
/** An evidence id as the index keeps it: 1 to 128 characters of 0x21–0x7E (the link grammar's `target.evidenceId`). */
const INDEXED_EVIDENCE_ID_RE = /^[\x21-\x7e]{1,128}$/;

/**
 * One row of the link index. `subjectDigest` is set on a statement of a link
 * record: the record at `evidenceId` is a link record, and the relation it
 * states (`rel`, towards `targetDigest`) is its subject's, whose digest this
 * is. It is `null` on every other row, the link record's own `subject` row
 * included.
 */
export interface LinkIndexRow extends EvidenceLinkRow {
  subjectDigest: string | null;
}

/**
 * What a page asks for. `rels` keeps the rows whose relation it names (an
 * empty list matches nothing); `statements: true` keeps only the statements
 * of link records. `limit` is 1 to 200, 100 when omitted.
 */
export interface LinkIndexQuery {
  rels?: readonly string[];
  limit?: number;
  cursor?: string;
  statements?: boolean;
}

/** One page of the index. `cursor` continues after its last row; `null` when there is no further row. */
export interface LinkIndexPage {
  rows: LinkIndexRow[];
  cursor: string | null;
}

/** Why a query of the index is refused. Never echoes the value. */
export type LinkIndexQueryErrorCode = 'invalid_target_digest' | 'invalid_limit' | 'invalid_cursor' | 'invalid_relation';

/** A query of the link index the index refuses. */
export class LinkIndexQueryError extends Error {
  constructor(
    readonly code: LinkIndexQueryErrorCode,
    readonly field: string,
    message: string,
  ) {
    super(`${field}: ${message}`);
    this.name = 'LinkIndexQueryError';
    Object.setPrototypeOf(this, LinkIndexQueryError.prototype);
  }
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * The index rows a record contributes, in link order: one per link that has
 * a relation name of the link grammar and a 64-hex target digest. A link
 * that is not well formed contributes none (the record's `links` row reports
 * it); a record without an evidence id of the index's form contributes none.
 */
export function linkIndexRows(envelope: EvidenceEnvelope | null | undefined): LinkIndexRow[] {
  const payload = (envelope as { payload?: unknown } | null | undefined)?.payload;
  if (!isPlainObject(payload)) return [];
  const evidenceId = payload.evidenceId;
  const links = payload.links;
  if (typeof evidenceId !== 'string' || !INDEXED_EVIDENCE_ID_RE.test(evidenceId) || !Array.isArray(links)) return [];
  const wellFormed = (link: unknown): link is { rel: string; target: { digest: string } } =>
    isPlainObject(link) &&
    isRelationName(link.rel) &&
    isPlainObject(link.target) &&
    typeof link.target.digest === 'string' &&
    BARE_DIGEST_RE.test(link.target.digest);
  const linkRecord = payload.aiSystemId === LINK_RECORD_AI_SYSTEM_ID;
  const subjectLink = linkRecord ? links.find((l) => wellFormed(l) && l.rel === 'subject') : undefined;
  const subjectDigest = subjectLink !== undefined && wellFormed(subjectLink) ? subjectLink.target.digest : null;
  const rows: LinkIndexRow[] = [];
  links.forEach((link, idx) => {
    if (!wellFormed(link)) return;
    rows.push({
      evidenceId,
      idx,
      rel: link.rel,
      targetDigest: link.target.digest,
      subjectDigest: linkRecord && link.rel !== 'subject' ? subjectDigest : null,
    });
  });
  return rows;
}

// ── Query validation and the cursor ───────────────────────────────────────

/** A query, checked: the limit resolved, the relations and the cursor decoded. */
export interface CheckedLinkIndexQuery {
  digest: string;
  rels: readonly string[] | null;
  limit: number;
  after: { evidenceId: string; idx: number } | null;
  statements: boolean;
}

/** Encode the position after which the next page starts. */
export function encodeLinkIndexCursor(row: { evidenceId: string; idx: number }): string {
  return Buffer.from(JSON.stringify([row.evidenceId, row.idx]), 'utf8').toString('base64url');
}

/** Decode a cursor, or throw `invalid_cursor`. */
export function decodeLinkIndexCursor(cursor: unknown): { evidenceId: string; idx: number } {
  const refuse = () => new LinkIndexQueryError('invalid_cursor', 'cursor', 'not a cursor this index returned');
  if (typeof cursor !== 'string' || cursor.length === 0 || cursor.length > 512 || !/^[A-Za-z0-9_-]+$/.test(cursor)) throw refuse();
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch {
    throw refuse();
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length !== 2 ||
    typeof parsed[0] !== 'string' ||
    !INDEXED_EVIDENCE_ID_RE.test(parsed[0]) ||
    typeof parsed[1] !== 'number' ||
    !Number.isSafeInteger(parsed[1]) ||
    parsed[1] < 0
  ) {
    throw refuse();
  }
  return { evidenceId: parsed[0], idx: parsed[1] };
}

/**
 * Check a query: `digest` 64 lowercase hex; `limit` an integer of 1 to 200
 * (100 when omitted); `rels`, when given, an array of at most 64 relation
 * names; `cursor` one this index returned.
 *
 * @throws LinkIndexQueryError
 */
export function checkLinkIndexQuery(digest: unknown, query: LinkIndexQuery | undefined): CheckedLinkIndexQuery {
  if (typeof digest !== 'string' || !BARE_DIGEST_RE.test(digest)) {
    throw new LinkIndexQueryError('invalid_target_digest', 'digest', 'must be 64 lowercase hex characters');
  }
  const q = query ?? {};
  if (!isPlainObject(q)) throw new LinkIndexQueryError('invalid_limit', 'options', 'must be an object');
  const limit = q.limit === undefined ? LINK_INDEX_DEFAULT_LIMIT : q.limit;
  if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > LINK_INDEX_MAX_LIMIT) {
    throw new LinkIndexQueryError('invalid_limit', 'limit', `must be an integer from 1 to ${LINK_INDEX_MAX_LIMIT}`);
  }
  let rels: readonly string[] | null = null;
  if (q.rels !== undefined) {
    if (!Array.isArray(q.rels) || q.rels.length > LINK_INDEX_MAX_RELS || !q.rels.every((r) => isRelationName(r))) {
      throw new LinkIndexQueryError(
        'invalid_relation',
        'rels',
        `must be an array of at most ${LINK_INDEX_MAX_RELS} relation names ([a-z][A-Za-z0-9]{0,31} or x-<org>.<name>)`,
      );
    }
    rels = [...new Set(q.rels as string[])];
  }
  const after = q.cursor === undefined ? null : decodeLinkIndexCursor(q.cursor);
  return { digest, rels, limit, after, statements: q.statements === true };
}

/** The page of `rows` (fetched with `limit + 1`) and its cursor. */
function pageOf(rows: LinkIndexRow[], limit: number): LinkIndexPage {
  const more = rows.length > limit;
  const page = more ? rows.slice(0, limit) : rows;
  return { rows: page, cursor: more ? encodeLinkIndexCursor(page[page.length - 1]) : null };
}

// ── SQLite ────────────────────────────────────────────────────────────────

interface SqliteLinkRow {
  evidence_id: string;
  idx: number;
  rel: string;
  target_digest: string;
  subject_digest: string | null;
}

const fromSqlRow = (r: SqliteLinkRow): LinkIndexRow => ({
  evidenceId: r.evidence_id,
  idx: Number(r.idx),
  rel: r.rel,
  targetDigest: r.target_digest,
  subjectDigest: r.subject_digest,
});

/** The insert statement, prepared once per connection. */
const sqliteInsertStatements = new WeakMap<Database.Database, Database.Statement>();

/** Write a record's rows. A row already held for the same (record, index) is kept. */
export function sqliteInsertLinkRows(db: Database.Database, rows: readonly LinkIndexRow[]): void {
  if (rows.length === 0) return;
  let insert = sqliteInsertStatements.get(db);
  if (insert === undefined) {
    insert = db.prepare('INSERT OR IGNORE INTO evidence_links (evidence_id, idx, rel, target_digest, subject_digest) VALUES (?, ?, ?, ?, ?)');
    sqliteInsertStatements.set(db, insert);
  }
  for (const r of rows) insert.run(r.evidenceId, r.idx, r.rel, r.targetDigest, r.subjectDigest);
}

/** One page of the rows naming `query.digest`. */
export function sqliteLinkIndexPage(db: Database.Database, query: CheckedLinkIndexQuery): LinkIndexPage {
  if (query.rels !== null && query.rels.length === 0) return { rows: [], cursor: null };
  const where: string[] = ['l.target_digest = ?'];
  const params: unknown[] = [query.digest];
  if (query.rels !== null) {
    // One relation is an equality, which the (target_digest, rel, …) index serves in key order.
    where.push(query.rels.length === 1 ? 'l.rel = ?' : `l.rel IN (${query.rels.map(() => '?').join(', ')})`);
    params.push(...query.rels);
  }
  if (query.statements) where.push('l.subject_digest IS NOT NULL');
  if (query.after !== null) {
    where.push('(l.evidence_id > ? OR (l.evidence_id = ? AND l.idx > ?))');
    params.push(query.after.evidenceId, query.after.evidenceId, query.after.idx);
  }
  where.push('EXISTS (SELECT 1 FROM envelopes e WHERE e.evidence_id = l.evidence_id)');
  params.push(query.limit + 1);
  const rows = db
    .prepare(
      `SELECT l.evidence_id, l.idx, l.rel, l.target_digest, l.subject_digest
         FROM evidence_links l
        WHERE ${where.join(' AND ')}
        ORDER BY l.evidence_id, l.idx
        LIMIT ?`,
    )
    .all(...params) as SqliteLinkRow[];
  return pageOf(rows.map(fromSqlRow), query.limit);
}

/** How many records the SQLite backfill reads per statement. */
const SQLITE_BACKFILL_BATCH = 500;

/**
 * Index every stored record that has links, in one transaction: run once,
 * when the index table is created on a store that already holds records. A
 * row whose envelope is not valid JSON is skipped.
 */
export function sqliteBackfillLinkIndex(db: Database.Database): void {
  const select = db.prepare(
    `SELECT rowid AS position, envelope FROM envelopes
      WHERE rowid > ?
        AND CASE WHEN json_valid(envelope) THEN json_type(envelope, '$.payload.links') END = 'array'
      ORDER BY rowid
      LIMIT ?`,
  );
  db.transaction(() => {
    // Read a batch, then write it: better-sqlite3 writes nothing while a statement is still iterating.
    for (let after = 0; ; ) {
      const batch = select.all(after, SQLITE_BACKFILL_BATCH) as Array<{ position: number; envelope: string }>;
      for (const row of batch) {
        let envelope: EvidenceEnvelope;
        try {
          envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
        } catch {
          continue;
        }
        sqliteInsertLinkRows(db, linkIndexRows(envelope));
      }
      if (batch.length < SQLITE_BACKFILL_BATCH) return;
      after = batch[batch.length - 1].position;
    }
  })();
}

// ── Postgres ──────────────────────────────────────────────────────────────

/** Write a record's rows in one statement. A row already held for the same (record, index) is kept. */
export async function postgresInsertLinkRows(client: PoolClient, rows: readonly LinkIndexRow[]): Promise<void> {
  if (rows.length === 0) return;
  await client.query(
    `INSERT INTO evidence_links (evidence_id, idx, rel, target_digest, subject_digest)
     SELECT * FROM unnest($1::text[], $2::int[], $3::text[], $4::text[], $5::text[])
     ON CONFLICT (evidence_id, idx) DO NOTHING`,
    [
      rows.map((r) => r.evidenceId),
      rows.map((r) => r.idx),
      rows.map((r) => r.rel),
      rows.map((r) => r.targetDigest),
      rows.map((r) => r.subjectDigest),
    ],
  );
}

/** One page of the rows naming `query.digest`, read through `db` (the adapter's pool, or a client). */
export async function postgresLinkIndexPage(db: Pool | PoolClient, query: CheckedLinkIndexQuery): Promise<LinkIndexPage> {
  if (query.rels !== null && query.rels.length === 0) return { rows: [], cursor: null };
  const where: string[] = ['l.target_digest = $1'];
  const params: unknown[] = [query.digest];
  if (query.rels !== null) {
    // One relation is an equality, which the (target_digest, rel, …) index serves in key order.
    params.push(query.rels.length === 1 ? query.rels[0] : query.rels);
    where.push(query.rels.length === 1 ? `l.rel = $${params.length}` : `l.rel = ANY($${params.length}::text[])`);
  }
  if (query.statements) where.push('l.subject_digest IS NOT NULL');
  if (query.after !== null) {
    params.push(query.after.evidenceId, query.after.idx);
    where.push(`(l.evidence_id, l.idx) > ($${params.length - 1}::text COLLATE "C", $${params.length}::int)`);
  }
  where.push('EXISTS (SELECT 1 FROM envelopes e WHERE e.evidence_id = l.evidence_id)');
  params.push(query.limit + 1);
  const result = await db.query<SqliteLinkRow>(
    `SELECT l.evidence_id, l.idx, l.rel, l.target_digest, l.subject_digest
       FROM evidence_links l
      WHERE ${where.join(' AND ')}
      ORDER BY l.evidence_id, l.idx
      LIMIT $${params.length}`,
    params,
  );
  return pageOf(result.rows.map(fromSqlRow), query.limit);
}

/** How many records the backfill reads per statement. */
const POSTGRES_BACKFILL_BATCH = 500;

/**
 * Index every stored record that has links, in batches by evidence id: run
 * once, inside the transaction that creates the index table on a store that
 * already holds records.
 */
export async function postgresBackfillLinkIndex(client: PoolClient): Promise<void> {
  let after = '';
  for (;;) {
    const batch = await client.query<{ evidence_id: string; envelope: EvidenceEnvelope }>(
      `SELECT evidence_id, envelope FROM envelopes
        WHERE jsonb_typeof(envelope -> 'payload' -> 'links') = 'array'
          AND evidence_id COLLATE "C" > $1 COLLATE "C"
        ORDER BY evidence_id COLLATE "C"
        LIMIT $2`,
      [after, POSTGRES_BACKFILL_BATCH],
    );
    if (batch.rows.length === 0) return;
    const rows = batch.rows.flatMap((r) => linkIndexRows(r.envelope));
    await postgresInsertLinkRows(client, rows);
    after = batch.rows[batch.rows.length - 1].evidence_id;
    if (batch.rows.length < POSTGRES_BACKFILL_BATCH) return;
  }
}

// ── Memory ────────────────────────────────────────────────────────────────

const compareRows = (a: LinkIndexRow, b: LinkIndexRow): number =>
  a.evidenceId < b.evidenceId ? -1 : a.evidenceId > b.evidenceId ? 1 : a.idx - b.idx;

/** One page of the rows naming `query.digest`, by scanning every record held. */
export function memoryLinkIndexPage(records: readonly EvidenceEnvelope[], query: CheckedLinkIndexQuery): LinkIndexPage {
  if (query.rels !== null && query.rels.length === 0) return { rows: [], cursor: null };
  const rels = query.rels === null ? null : new Set(query.rels);
  const after = query.after;
  const rows = records
    .flatMap((envelope) => linkIndexRows(envelope))
    .filter(
      (r) =>
        r.targetDigest === query.digest &&
        (rels === null || rels.has(r.rel)) &&
        (!query.statements || r.subjectDigest !== null) &&
        (after === null || compareRows(r, { ...r, evidenceId: after.evidenceId, idx: after.idx }) > 0),
    )
    .sort(compareRows);
  return pageOf(rows.slice(0, query.limit + 1), query.limit);
}
