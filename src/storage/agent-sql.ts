/**
 * The agent catalog's statements and rules (Record §6.9), shared by the
 * SQLite, Postgres and memory parts of `agentsStorageExtension`
 * (`ddl/agents.ts`).
 *
 * The catalog keeps each registered `tzun-agent/1` descriptor under its
 * digest, as the exact canonical bytes that were hashed, with three lookup
 * columns (`name`, `organization`, `parent`) that verification never reads.
 * Rows are immutable and never removed: a record that names an agent keeps
 * naming the bytes it was captured against.
 *
 *   - `putAgentDescriptor(descriptor)` takes a JSON copy of the descriptor
 *     (each member read once), checks the copy (the grammar, the writer
 *     limits, and no U+0000 in a lookup column), serialises it with its sets
 *     sorted, and stores it under `sha256:` + hex(SHA-256(bytes)).
 *     Registering the same bytes again answers `alreadyExisted: true` and
 *     writes nothing. A row already held under the digest whose bytes differ
 *     is a catalog that was written around this method, and is refused
 *     (`AgentDescriptorConflictError`). On Postgres a registration holds the
 *     transaction advisory lock {@link AGENT_CATALOG_LOCK_KEY}, so rows are
 *     numbered and committed in one order.
 *   - `getAgentDescriptor(digest)` returns the row as stored, or `null`.
 *   - `listAgentDescriptors({ name?, organization?, limit?, cursor? })`
 *     pages through the catalog in registration order (the row's `seq`),
 *     `limit` rows at a time (default 100, at most 200). The cursor is opaque
 *     to the caller; it names the last row of the page, and `null` means no
 *     row follows.
 */
import { createHash } from 'crypto';
import type Database from 'better-sqlite3';
import type { Pool } from 'pg';
import { InvalidPaginationError, agentDescriptorViolation, canonicalSerializeAgentDescriptor } from '@tzun/engine';
import type { AgentDescriptor, AgentDescriptorRow } from '@tzun/engine';
import type { ExtensionMethods, PostgresExtensionDb } from './extensions';

/** How many rows a page holds when the caller names no `limit`. */
export const AGENT_LIST_DEFAULT_LIMIT = 100;
/** The most rows one page may hold. */
export const AGENT_LIST_MAX_LIMIT = 200;

/**
 * The Postgres transaction advisory lock (one bigint key) every registration
 * holds from before it reads the digest until it commits. `seq` is an
 * identity column, drawn at insert and seen at commit; holding the lock makes
 * the order rows are numbered in the order they become visible, so a caller
 * paging by cursor never passes a row that commits later with a lower `seq`.
 * The SDK's other advisory keys are 2026052501 (`ensureTables()`, session
 * lock) and (2026091801, hashtext(evidence_id)) (custody appends).
 */
export const AGENT_CATALOG_LOCK_KEY = 2026100101;

const PREFIXED_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CURSOR_RE = /^[1-9][0-9]{0,15}$/;

// ── Errors ─────────────────────────────────────────────────────────────────

/** A descriptor that breaks the `tzun-agent/1` grammar or a writer limit (Record §6.9, §11). */
export class InvalidAgentDescriptorError extends Error {
  readonly code = 'invalid_agent_descriptor' as const;
  readonly field = 'descriptor' as const;
  /** The rule the descriptor breaks. Names the member and the rule, never a value. */
  readonly rule: string;
  constructor(rule: string) {
    super(`The agent descriptor is refused: ${rule}.`);
    this.name = 'InvalidAgentDescriptorError';
    this.rule = rule;
    Object.setPrototypeOf(this, InvalidAgentDescriptorError.prototype);
  }
}

/**
 * A store that keeps no agent catalog: an adapter without the catalog
 * methods (a custom adapter), or one whose methods answer
 * `agent_not_supported_by_store` (the cloud transport against a platform that
 * does not serve the agent endpoints).
 */
export class AgentCatalogUnsupportedError extends Error {
  readonly code = 'agent_not_supported_by_store' as const;
  constructor() {
    super('This store keeps no agent catalog: it cannot register, read or list agent descriptors.');
    this.name = 'AgentCatalogUnsupportedError';
    Object.setPrototypeOf(this, AgentCatalogUnsupportedError.prototype);
  }
}

/**
 * The catalog already holds a row under the digest whose bytes are not the
 * bytes being registered: the row was written around `putAgentDescriptor`
 * (no other path writes a row under a digest its bytes do not hash to).
 */
export class AgentDescriptorConflictError extends Error {
  readonly code = 'agent_descriptor_conflict' as const;
  constructor(readonly digest: string) {
    super(`The agent catalog holds other bytes under ${digest}; the row does not hash to its digest.`);
    this.name = 'AgentDescriptorConflictError';
    Object.setPrototypeOf(this, AgentDescriptorConflictError.prototype);
  }
}

// ── What a registration writes ─────────────────────────────────────────────

/** One catalog row, ready to insert. */
export interface AgentDescriptorWrite {
  /** `sha256:` and the lowercase hex SHA-256 of `canonicalBytes`. */
  digest: string;
  /** The descriptor's canonical bytes, its sets sorted by UTF-8 bytes. */
  canonicalBytes: string;
  name: string;
  organization: string;
  parent: string | null;
  /** ISO 8601 UTC with milliseconds. */
  registeredAt: string;
}

/** `sha256:` and the lowercase hex SHA-256 of a string's UTF-8 bytes. */
export function prefixedSha256(text: string): string {
  return 'sha256:' + createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Whether `value` has the form of an agent descriptor digest (`sha256:` and 64 lowercase hex). */
export function isAgentDescriptorDigest(value: unknown): value is string {
  return typeof value === 'string' && PREFIXED_DIGEST_RE.test(value);
}

/**
 * The descriptor a registration checks, stores and hashes: a JSON copy of
 * the caller's value, checked against the grammar, the writer limits, and no
 * U+0000 in `name` or `operator.organization`. Those two are also lookup
 * columns, and a Postgres `text` value cannot hold U+0000 (the canonical
 * bytes escape it). The copy reads each member once, so a getter that
 * answers differently on a later read cannot change what was checked, and it
 * turns an array hole into `null`, which the grammar refuses. Throws
 * {@link InvalidAgentDescriptorError}, also for a value that has no JSON form
 * (a cycle, a BigInt, a member that throws).
 */
export function checkedAgentDescriptor(descriptor: unknown): AgentDescriptor {
  let copy: unknown;
  try {
    const text = JSON.stringify(descriptor);
    copy = text === undefined ? undefined : JSON.parse(text);
  } catch {
    throw new InvalidAgentDescriptorError('an agent descriptor must be a JSON value');
  }
  const violation = agentDescriptorViolation(copy);
  if (violation !== null) throw new InvalidAgentDescriptorError(violation);
  const d = copy as AgentDescriptor;
  if (d.name.includes('\u0000') || d.operator.organization.includes('\u0000')) {
    throw new InvalidAgentDescriptorError('name and operator.organization hold no U+0000');
  }
  return d;
}

/**
 * Check a descriptor ({@link checkedAgentDescriptor}) and build the row it is
 * stored as, from the checked copy only. Throws
 * {@link InvalidAgentDescriptorError}.
 */
export function agentDescriptorWrite(descriptor: unknown, now: Date = new Date()): AgentDescriptorWrite {
  const d = checkedAgentDescriptor(descriptor);
  const canonicalBytes = canonicalSerializeAgentDescriptor(d);
  return {
    digest: prefixedSha256(canonicalBytes),
    canonicalBytes,
    name: d.name,
    organization: d.operator.organization,
    parent: d.parent,
    registeredAt: now.toISOString(),
  };
}

// ── What a listing asks for ────────────────────────────────────────────────

/** A listing request, checked. */
export interface AgentListQuery {
  name: string | null;
  organization: string | null;
  limit: number;
  /** List rows whose `seq` is above this; `null` from the first row. */
  after: number | null;
}

/**
 * A listing request checked as every store checks it, with the cursor kept
 * as the string the caller passed: the cloud transport hands the platform's
 * own cursor back to it unread.
 */
export interface AgentListRequest {
  name: string | null;
  organization: string | null;
  limit: number;
  /** The cursor a previous page answered; `null` from the first row. */
  cursor: string | null;
}

type AgentListFilter = Parameters<NonNullable<ExtensionMethods['listAgentDescriptors']>>[0];

/** The longest cursor a listing passes on: the cloud transport's are the platform's (a descriptor digest is 71). */
const AGENT_LIST_CURSOR_MAX = 512;

/**
 * Check a listing filter as every store checks it: `name` and
 * `organization` strings when given, `limit` an integer from 1 to 200
 * (default 100), `cursor` a non-empty string of at most 512 printable ASCII
 * characters (0x21-0x7E). Throws `InvalidPaginationError` for a bad `limit`
 * or `cursor` and `TypeError` for a filter that is not an object or a lookup
 * value that is not a string. A store then reads the cursor as its own: the
 * local stores take only the decimal ones they hand out ({@link agentListQuery}).
 */
export function agentListRequest(filter: AgentListFilter): AgentListRequest {
  if (filter === undefined || filter === null) {
    return { name: null, organization: null, limit: AGENT_LIST_DEFAULT_LIMIT, cursor: null };
  }
  if (typeof filter !== 'object' || Array.isArray(filter)) throw new TypeError('The agent listing filter must be an object.');
  const { name, organization, limit, cursor } = filter;
  if (name !== undefined && typeof name !== 'string') throw new TypeError('The agent listing filter `name` must be a string.');
  if (organization !== undefined && typeof organization !== 'string') {
    throw new TypeError('The agent listing filter `organization` must be a string.');
  }
  let pageSize = AGENT_LIST_DEFAULT_LIMIT;
  if (limit !== undefined) {
    if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > AGENT_LIST_MAX_LIMIT) {
      throw new InvalidPaginationError('limit', limit);
    }
    pageSize = limit;
  }
  if (
    cursor !== undefined &&
    (typeof cursor !== 'string' || cursor.length === 0 || cursor.length > AGENT_LIST_CURSOR_MAX || !/^[\x21-\x7e]+$/.test(cursor))
  ) {
    throw new InvalidPaginationError('cursor', cursor);
  }
  return { name: name ?? null, organization: organization ?? null, limit: pageSize, cursor: cursor ?? null };
}

/**
 * Check a listing filter for a local store ({@link agentListRequest}), whose
 * cursor is one this catalog handed out: a decimal registration sequence.
 * Throws `InvalidPaginationError` for any other cursor.
 */
export function agentListQuery(filter: AgentListFilter): AgentListQuery {
  const { name, organization, limit, cursor } = agentListRequest(filter);
  let after: number | null = null;
  if (cursor !== null) {
    if (!CURSOR_RE.test(cursor) || !Number.isSafeInteger(Number(cursor))) {
      throw new InvalidPaginationError('cursor', cursor);
    }
    after = Number(cursor);
  }
  return { name, organization, limit, after };
}

/**
 * One page from the rows a query read: the query reads `limit + 1` rows in
 * `seq` order, so a row past the page means another page follows, and the
 * cursor names the page's last row.
 */
export function agentPage(
  rows: ReadonlyArray<AgentDescriptorRow & { seq: number }>,
  limit: number,
): { rows: AgentDescriptorRow[]; cursor: string | null } {
  const page = rows.slice(0, limit);
  const cursor = rows.length > limit && page.length > 0 ? String(page[page.length - 1].seq) : null;
  return { rows: page.map(({ seq: _seq, ...row }) => row), cursor };
}

// ── SQLite ─────────────────────────────────────────────────────────────────

interface SqliteAgentRow {
  digest: string;
  canonical_bytes: string;
  name: string;
  organization: string;
  parent: string | null;
  registered_at: string;
  seq: number;
}

function fromSqlite(row: SqliteAgentRow): AgentDescriptorRow & { seq: number } {
  return {
    digest: row.digest,
    canonicalBytes: row.canonical_bytes,
    name: row.name,
    organization: row.organization,
    parent: row.parent,
    registeredAt: row.registered_at,
    seq: row.seq,
  };
}

const SQLITE_COLUMNS = 'digest, canonical_bytes, name, organization, parent, registered_at, seq';

/** The catalog methods over a SQLite connection. */
export function sqliteAgentMethods(db: Database.Database): ExtensionMethods {
  const byDigest = db.prepare(`SELECT ${SQLITE_COLUMNS} FROM agent_descriptors WHERE digest = ?`);
  const insert = db.prepare(
    `INSERT INTO agent_descriptors (${SQLITE_COLUMNS})
     VALUES (?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM agent_descriptors))`,
  );
  const register = db.transaction((write: AgentDescriptorWrite): boolean => {
    const held = byDigest.get(write.digest) as SqliteAgentRow | undefined;
    if (held) {
      if (held.canonical_bytes !== write.canonicalBytes) throw new AgentDescriptorConflictError(write.digest);
      return true;
    }
    insert.run(write.digest, write.canonicalBytes, write.name, write.organization, write.parent, write.registeredAt);
    return false;
  });
  return {
    async putAgentDescriptor(descriptor: AgentDescriptor) {
      const write = agentDescriptorWrite(descriptor);
      const alreadyExisted = register.immediate(write);
      return { digest: write.digest, alreadyExisted };
    },
    async getAgentDescriptor(digest: string) {
      if (!isAgentDescriptorDigest(digest)) return null;
      const row = byDigest.get(digest) as SqliteAgentRow | undefined;
      if (!row) return null;
      const { seq: _seq, ...out } = fromSqlite(row);
      return out;
    },
    async listAgentDescriptors(filter?: AgentListFilter) {
      const q = agentListQuery(filter);
      const rows = db
        .prepare(
          `SELECT ${SQLITE_COLUMNS} FROM agent_descriptors
            WHERE (? IS NULL OR name = ?) AND (? IS NULL OR organization = ?) AND seq > ?
            ORDER BY seq ASC LIMIT ?`,
        )
        .all(q.name, q.name, q.organization, q.organization, q.after ?? 0, q.limit + 1) as SqliteAgentRow[];
      return agentPage(rows.map(fromSqlite), q.limit);
    },
  };
}

// ── Postgres ───────────────────────────────────────────────────────────────

interface PostgresAgentRow {
  digest: string;
  canonical_bytes: string;
  name: string;
  organization: string;
  parent: string | null;
  registered_at: Date;
  seq: string;
}

function fromPostgres(row: PostgresAgentRow): AgentDescriptorRow & { seq: number } {
  return {
    digest: row.digest,
    canonicalBytes: row.canonical_bytes,
    name: row.name,
    organization: row.organization,
    parent: row.parent,
    registeredAt: row.registered_at.toISOString(),
    seq: Number(row.seq),
  };
}

const POSTGRES_COLUMNS = 'digest, canonical_bytes, name, organization, parent, registered_at, seq';

/**
 * The catalog methods over a Postgres pool. A registration runs in one
 * transaction under {@link AGENT_CATALOG_LOCK_KEY}: it reads the digest, and
 * inserts only when no row holds it, so registering bytes the catalog holds
 * draws no `seq`.
 */
export function postgresAgentMethods(db: Pick<PostgresExtensionDb, 'pool' | 'inTransaction'>): ExtensionMethods {
  const { pool } = db;
  const read = async (client: Pick<Pool, 'query'>, digest: string): Promise<PostgresAgentRow | undefined> =>
    (await client.query<PostgresAgentRow>(`SELECT ${POSTGRES_COLUMNS} FROM agent_descriptors WHERE digest = $1`, [digest]))
      .rows[0];
  return {
    async putAgentDescriptor(descriptor: AgentDescriptor) {
      const write = agentDescriptorWrite(descriptor);
      const alreadyExisted = await db.inTransaction(async (client) => {
        await client.query('SELECT pg_advisory_xact_lock($1)', [AGENT_CATALOG_LOCK_KEY]);
        const held = await read(client, write.digest);
        if (held === undefined) {
          // ON CONFLICT covers a row inserted around this method, which takes no lock.
          const inserted = await client.query(
            `INSERT INTO agent_descriptors (digest, canonical_bytes, name, organization, parent, registered_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (digest) DO NOTHING`,
            [write.digest, write.canonicalBytes, write.name, write.organization, write.parent, write.registeredAt],
          );
          if (inserted.rowCount === 1) return false;
        }
        const row = held ?? (await read(client, write.digest));
        if (!row || row.canonical_bytes !== write.canonicalBytes) throw new AgentDescriptorConflictError(write.digest);
        return true;
      });
      return { digest: write.digest, alreadyExisted };
    },
    async getAgentDescriptor(digest: string) {
      if (!isAgentDescriptorDigest(digest)) return null;
      const row = await read(pool, digest);
      if (!row) return null;
      const { seq: _seq, ...out } = fromPostgres(row);
      return out;
    },
    async listAgentDescriptors(filter?: AgentListFilter) {
      const q = agentListQuery(filter);
      const result = await pool.query<PostgresAgentRow>(
        `SELECT ${POSTGRES_COLUMNS} FROM agent_descriptors
          WHERE ($1::text IS NULL OR name = $1) AND ($2::text IS NULL OR organization = $2) AND seq > $3
          ORDER BY seq ASC LIMIT $4`,
        [q.name, q.organization, q.after ?? 0, q.limit + 1],
      );
      return agentPage(result.rows.map(fromPostgres), q.limit);
    },
  };
}

// ── Memory ─────────────────────────────────────────────────────────────────

/** The memory adapter's catalog: rows by digest, in registration order. */
export interface MemoryAgentCatalog {
  byDigest: Map<string, AgentDescriptorRow & { seq: number }>;
  nextSeq: number;
}

export function createMemoryAgentCatalog(): MemoryAgentCatalog {
  return { byDigest: new Map(), nextSeq: 1 };
}

/** The catalog methods over the memory adapter's state. Every row returned is a copy. */
export function memoryAgentMethods(state: MemoryAgentCatalog): ExtensionMethods {
  return {
    async putAgentDescriptor(descriptor: AgentDescriptor) {
      const write = agentDescriptorWrite(descriptor);
      const held = state.byDigest.get(write.digest);
      if (held) {
        if (held.canonicalBytes !== write.canonicalBytes) throw new AgentDescriptorConflictError(write.digest);
        return { digest: write.digest, alreadyExisted: true };
      }
      state.byDigest.set(write.digest, { ...write, seq: state.nextSeq++ });
      return { digest: write.digest, alreadyExisted: false };
    },
    async getAgentDescriptor(digest: string) {
      const held = isAgentDescriptorDigest(digest) ? state.byDigest.get(digest) : undefined;
      if (!held) return null;
      const { seq: _seq, ...out } = held;
      return out;
    },
    async listAgentDescriptors(filter?: AgentListFilter) {
      const q = agentListQuery(filter);
      const rows: Array<AgentDescriptorRow & { seq: number }> = [];
      // Map iteration is insertion order, which is `seq` order.
      for (const row of state.byDigest.values()) {
        if (row.seq <= (q.after ?? 0)) continue;
        if (q.name !== null && row.name !== q.name) continue;
        if (q.organization !== null && row.organization !== q.organization) continue;
        rows.push({ ...row });
        if (rows.length > q.limit) break;
      }
      return agentPage(rows, q.limit);
    },
  };
}
