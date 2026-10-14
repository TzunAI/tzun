/**
 * On Postgres, no row of `credential_events`, `custody_entries`, `logs` or
 * `anchor_publications` is written ahead of the rows it follows.
 *
 * The SDK reads these four tables in id order and names no id when it writes
 * one. A `BIGSERIAL` column still takes an explicit id, and a row written
 * below the last reads ahead of the rows it follows. On `credential_events`
 * that is a key swap: a credential's first registration is the one that
 * counts, so one plain INSERT at `seq` 0 would put another public key on a
 * registered credential. SQLite refuses an explicit id below the last
 * (`<table>_block_backdated_<id>`, sqlite-log-insert-guards.test.ts and
 * sqlite-insert-guards.test.ts); these are the Postgres twins
 * (`postgresBackdatedIdGuard` in src/storage/append-only.ts):
 *
 *   - an id below one visible to the INSERT is refused;
 *   - an id the table's sequence did not hand the insert is refused, above
 *     the last included;
 *   - an id the sequence handed out is never refused, even one whose writer
 *     waited while a higher id committed: Postgres commits sequence values
 *     out of order, so the guard reads the INSERT statement's snapshot and
 *     not the rows committed since;
 *   - every row takes an id the guard draws as it is written, so it lands
 *     after every row committed before it, even from a REPEATABLE READ or
 *     SERIALIZABLE transaction whose snapshot predates them;
 *   - the guard reads the table its trigger is on and pins its search_path,
 *     so a temporary table, or an operator or currval on a schema the
 *     inserting session puts first, does not stand in for the real ones.
 *
 * Four cases are writes the guards must let through: the store's own,
 * concurrent default inserts, a drawn value written out, and an INSERT
 * role's inserts with no id.
 *
 * Every attack is a raw statement on a connection of its own, the way a
 * least-privileged INSERT role would issue it; the name-resolution cases run
 * as such a role. Runs when the Postgres legs do
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own.
 */
import { createHash, randomBytes } from 'node:crypto';
import { Client, Pool } from 'pg';
import { canonicalCustodyMetadata, computeCustodyEntryHash } from '@tzun/engine';
import type { EvidenceEnvelope } from '@tzun/engine';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import {
  anchorStoreFor,
  evidenceLogOrigin,
  logStoreFor,
  type AnchorStore,
  type LogRecord,
  type LogStore,
  type NewLogCheckpoint,
} from '../../src/storage/log-store';
import type { AsyncCredentialStore, StoredCredential } from '../../src/attestation/credential-store';
import { makeEnvelope, makeRelink } from './storage-conformance/fixtures';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const pgSchema = pgSuiteSchema('backdated_id');
const describeLive = PG_TESTS_ENABLED ? describe : describe.skip;

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

const BELOW_THE_LAST = /must be above every existing/;
const NOT_DRAWN = /is not the one its sequence handed this insert/;

const CHAIN = 'eip155:31337';
const GOODKEY = 'GOODKEY';
const MALLORYKEY = 'MALLORYKEY';

/** Every guard this file is about: table, function, trigger. */
const GUARDS = [
  { table: 'credential_events', fn: 'credential_events_block_backdated_seq', trigger: 'credential_events_block_backdated_seq_trigger' },
  { table: 'custody_entries', fn: 'custody_entries_block_backdated_id', trigger: 'custody_entries_block_backdated_id_trigger' },
  { table: 'logs', fn: 'logs_block_backdated_id', trigger: 'logs_block_backdated_id_trigger' },
  { table: 'anchor_publications', fn: 'anchor_publications_block_backdated_id', trigger: 'anchor_publications_block_backdated_id_trigger' },
] as const;

type Row = Record<string, unknown>;

const credential = (credentialId: string, publicKey: string): StoredCredential => ({
  credentialId,
  publicKey,
  userId: 'jane@acme.example',
  algorithm: 'ES256',
  counter: 0,
  status: 'active',
  registeredAt: '2026-09-27T00:00:00.000Z',
});

function checkpointFor(log: LogRecord, treeSize: number): NewLogCheckpoint {
  const root = hex(`root-${log.origin}-${treeSize}`);
  const body = `${log.origin}\n${treeSize}\n${Buffer.from(root, 'hex').toString('base64')}\n`;
  return {
    logId: log.logId,
    treeSize,
    root,
    body,
    bodyDigest: createHash('sha256').update(body).digest('hex'),
    compactRange: [root],
    prevAnchoredSize: null,
    consistencyProof: null,
    anchorLeafIndex: null,
    epochId: null,
  };
}

/** `INSERT INTO table (columns) VALUES ($1, ...)` for `row`, with `row`'s values in column order. */
function insertOf(table: string, row: Row): [string, unknown[]] {
  const columns = Object.keys(row);
  return [`INSERT INTO ${table} (${columns.join(', ')}) VALUES (${columns.map((_, i) => `$${i + 1}`).join(', ')})`, columns.map((c) => row[c])];
}

describeLive('Postgres: no row is written ahead of the rows it follows', () => {
  jest.setTimeout(60_000);

  let adapter: PostgresStorageAdapter;
  let pool: Pool;
  let logs: LogStore;
  let anchors: AnchorStore;
  let credentials: AsyncCredentialStore;
  let anchorLog: LogRecord;

  beforeEach(async () => {
    await pgSchema.empty();
    adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    pool = new Pool({ connectionString: pgSchema.url });
    logs = logStoreFor(adapter)!;
    anchors = anchorStoreFor(adapter)!;
    credentials = adapter.credentialStore();

    // Three records, and a relink of ev-2 that ledgers a `relinked` custody entry.
    for (const n of [1, 2, 3]) await adapter.store(makeEnvelope({ evidenceId: `ev-${n}`, sequenceNumber: n }));
    await adapter.applyRelink(
      makeRelink({
        id: 'rlk-1',
        modifiedLinks: [{ evidenceId: 'ev-2', sequenceNumber: 2, previousChainLink: null, newChainLink: hex('relinked-link') }],
      }),
      [{
        evidenceId: 'ev-2',
        entry: { timestamp: '2026-09-27T10:00:00.000Z', actor: 'alice@acme.example', action: 'relinked', systemId: 'tzun-recovery' },
      }],
    );

    // The anchor log: three leaves, checkpoints at sizes 1 to 3, a publication at size 1.
    anchorLog = await anchors.ensureStoreLog('anchors');
    await anchors.appendLogLeaves(anchorLog.logId, [0, 1, 2].map((i) => ({
      leafIndex: i, leafDigest: hex(`anchor-leaf-${i}`), sourceRef: `cp-${i}`,
    })));
    for (const size of [1, 2, 3]) await anchors.insertLogCheckpoint(checkpointFor(anchorLog, size));
    await anchors.insertAnchorPublication({
      epochId: 1, anchorSize: 1, p: checkpointFor(anchorLog, 1).bodyDigest, kind: 'evm-calldata/1', chain: CHAIN,
    });

    // Two credentials; the second is revoked.
    await credentials.register(credential('cred-1', GOODKEY));
    await credentials.register(credential('cred-2', GOODKEY));
    await credentials.revoke('cred-2', { reason: 'lost' });
  });

  afterEach(async () => {
    await pool?.end();
    await adapter?.close();
  });

  const all = async (sql: string, params: unknown[] = []): Promise<Row[]> => (await pool.query(sql, params)).rows;
  const maxOf = async (table: string, column: string): Promise<number> =>
    Number((await all(`SELECT MAX(${column}) AS m FROM ${table}`))[0].m);
  /** Every row of `table` in id order: what a refused statement must leave exactly as it was. */
  const snapshot = (table: string, column: string) => all(`SELECT * FROM ${table} ORDER BY ${column}`);

  /** Run one statement on a connection of its own, and return its error message, or throw if it went through. */
  async function refusal(sql: string, params: unknown[]): Promise<string> {
    const client = new Client({ connectionString: pgSchema.url });
    await client.connect();
    try {
      await client.query(sql, params);
    } catch (err) {
      return String((err as Error).message);
    } finally {
      await client.end();
    }
    throw new Error('expected the statement to be refused, but it went through');
  }

  const plantedRegistration = (overrides: Row = {}): Row => ({
    event_id: 'planted',
    credential_id: 'cred-1',
    event_type: 'registered',
    occurred_at: '2026-09-26T00:00:00Z',
    user_id: 'alice',
    public_key: MALLORYKEY,
    algorithm: 'ES256',
    ...overrides,
  });

  /** The custody row the adapter would write next for ev-2: it extends the ledger's tail and recomputes. */
  async function nextCustodyRow(): Promise<Row> {
    const [{ envelope }] = await all('SELECT envelope FROM envelopes WHERE evidence_id = $1', ['ev-2']);
    const [tail] = await all('SELECT entry_hash FROM custody_entries WHERE evidence_id = $1 ORDER BY id DESC LIMIT 1', ['ev-2']);
    const fields = {
      evidenceId: 'ev-2',
      canonicalDigest: (envelope as EvidenceEnvelope).integrity.canonicalDigest,
      action: 'reviewed',
      actor: 'mallory@acme.example',
      timestamp: '2026-09-27T11:00:00.000Z',
      systemId: 'tzun-recovery',
    };
    const prevEntryHash = tail.entry_hash as string;
    return {
      evidence_id: fields.evidenceId,
      chain_id: 'default',
      canonical_digest: fields.canonicalDigest,
      action: fields.action,
      actor: fields.actor,
      ts: fields.timestamp,
      system_id: fields.systemId,
      metadata: null,
      metadata_canonical: canonicalCustodyMetadata(null),
      prev_entry_hash: prevEntryHash,
      entry_hash: computeCustodyEntryHash({ ...fields, prevEntryHash, metadata: null }),
      recovery_id: null,
    };
  }

  /** An evidence log for a chain that has none: a `logs` row logs_verify_insert accepts. */
  async function freshLogRow(overrides: Row = {}): Promise<Row> {
    const identity = await logs.getStoreIdentity();
    return {
      origin: evidenceLogOrigin(identity.ns, identity.storeId, 'chain-z'),
      kind: 'evidence',
      chain_id: 'chain-z',
      ...overrides,
    };
  }

  /** A prepared publication that anchor_publications_verify_insert accepts, at anchor size 2. */
  const freshPublicationRow = (overrides: Row = {}): Row => ({
    epoch_id: 2,
    anchor_size: 2,
    p: checkpointFor(anchorLog, 2).bodyDigest,
    kind: 'evm-calldata/1',
    state: 'prepared',
    chain: CHAIN,
    ...overrides,
  });

  describe('credential_events', () => {
    it('the key swap: a registration planted at seq 0 is refused, and the credential keeps its key', async () => {
      expect((await credentials.getByCredentialId('cred-1'))?.publicKey).toBe(GOODKEY);
      const before = await snapshot('credential_events', 'seq');
      expect(await refusal(...insertOf('credential_events', plantedRegistration({ seq: 0 })))).toMatch(BELOW_THE_LAST);
      expect(await snapshot('credential_events', 'seq')).toEqual(before);
      expect((await credentials.getByCredentialId('cred-1'))?.publicKey).toBe(GOODKEY);
    });

    it('a seq below the last is refused, whether a row holds it or not', async () => {
      const last = await maxOf('credential_events', 'seq');
      for (const seq of [-1, 1, last - 1]) {
        expect(await refusal(...insertOf('credential_events', plantedRegistration({ seq, event_id: `planted-${seq}` })))).toMatch(BELOW_THE_LAST);
      }
    });

    it('an explicit seq above the last that the sequence did not hand out is refused, and later registrations still go through', async () => {
      const last = await maxOf('credential_events', 'seq');
      expect(await refusal(...insertOf('credential_events', plantedRegistration({ seq: last + 1_000, credential_id: 'cred-9' })))).toMatch(NOT_DRAWN);
      expect(await refusal(...insertOf('credential_events', plantedRegistration({ seq: last + 1, credential_id: 'cred-9' })))).toMatch(NOT_DRAWN);
      await credentials.register(credential('cred-3', GOODKEY));
      expect((await credentials.list()).map((c) => c.credentialId)).toEqual(['cred-1', 'cred-2', 'cred-3']);
    });

    it('a seq drawn in an earlier transaction is refused once a later seq has committed (READ COMMITTED)', async () => {
      const holder = new Client({ connectionString: pgSchema.url });
      await holder.connect();
      try {
        const held = Number((await holder.query("SELECT nextval(pg_get_serial_sequence('credential_events', 'seq')) AS n")).rows[0].n);
        await credentials.register(credential('cred-3', GOODKEY));
        const [sql, params] = insertOf('credential_events', plantedRegistration({ seq: held, credential_id: 'cred-3' }));
        await expect(holder.query(sql, params)).rejects.toThrow(BELOW_THE_LAST);
        expect((await credentials.getByCredentialId('cred-3'))?.publicKey).toBe(GOODKEY);
      } finally {
        await holder.end();
      }
    });

    it('the seq the sequence just handed the session is accepted when written out: it is the default’s own value', async () => {
      const client = new Client({ connectionString: pgSchema.url });
      await client.connect();
      try {
        const drawn = Number((await client.query("SELECT nextval(pg_get_serial_sequence('credential_events', 'seq')) AS n")).rows[0].n);
        await client.query(...insertOf('credential_events', plantedRegistration({ seq: drawn, event_id: 'drawn', credential_id: 'cred-4', public_key: GOODKEY })));
      } finally {
        await client.end();
      }
      const events = await credentials.history();
      expect(events[events.length - 1].eventId).toBe('drawn');
    });

    it.each(['REPEATABLE READ', 'SERIALIZABLE'])(
      'a seq drawn in a %s transaction, written once a later registration has committed, lands after it: the credential keeps its key',
      async (isolation) => {
        // The transaction's snapshot is taken by its first statement, the
        // draw, so the registration committed after it is not visible to the
        // guard's read of the last seq; the held value passes both checks.
        const holder = new Client({ connectionString: pgSchema.url });
        await holder.connect();
        try {
          await holder.query(`BEGIN ISOLATION LEVEL ${isolation}`);
          const held = Number((await holder.query("SELECT nextval(pg_get_serial_sequence('credential_events', 'seq')) AS n")).rows[0].n);
          await credentials.register(credential('cred-3', GOODKEY));
          const [victim] = await all("SELECT seq FROM credential_events WHERE credential_id = 'cred-3'");
          expect(held).toBeLessThan(Number(victim.seq));
          const [sql, params] = insertOf('credential_events', plantedRegistration({ seq: held, event_id: 'held', credential_id: 'cred-3' }));
          const landed = Number((await holder.query(`${sql} RETURNING seq`, params)).rows[0].seq);
          await holder.query('COMMIT');
          expect(landed).toBeGreaterThan(Number(victim.seq));
          expect((await credentials.getByCredentialId('cred-3'))?.publicKey).toBe(GOODKEY);
        } finally {
          await holder.query('ROLLBACK').catch(() => undefined);
          await holder.end();
        }
      },
    );
  });

  describe('custody_entries', () => {
    it('a row that extends the tail, written at an explicit id below it, is refused', async () => {
      const before = await snapshot('custody_entries', 'id');
      expect(await refusal(...insertOf('custody_entries', { id: 0, ...(await nextCustodyRow()) }))).toMatch(BELOW_THE_LAST);
      expect(await snapshot('custody_entries', 'id')).toEqual(before);
      expect((await adapter.listCustodyEntries('ev-2')).map((e) => e.action)).toEqual(['relinked']);
    });

    it('an explicit id above the last that the sequence did not hand out is refused; the same row with no id is accepted and reads last', async () => {
      const last = await maxOf('custody_entries', 'id');
      const row = await nextCustodyRow();
      expect(await refusal(...insertOf('custody_entries', { id: last + 10, ...row }))).toMatch(NOT_DRAWN);
      await pool.query(...insertOf('custody_entries', row));
      expect((await adapter.listCustodyEntries('ev-2')).map((e) => e.action)).toEqual(['relinked', 'reviewed']);
    });
  });

  describe('logs', () => {
    it('an explicit log_id below the last is refused', async () => {
      const before = await logs.listLogs();
      expect(await refusal(...insertOf('logs', await freshLogRow({ log_id: 0 })))).toMatch(BELOW_THE_LAST);
      expect(await logs.listLogs()).toEqual(before);
    });

    it('an explicit log_id above the last that the sequence did not hand out is refused; the same row with no id is accepted and reads last', async () => {
      const last = await maxOf('logs', 'log_id');
      expect(await refusal(...insertOf('logs', await freshLogRow({ log_id: last + 10 })))).toMatch(NOT_DRAWN);
      await pool.query(...insertOf('logs', await freshLogRow()));
      const listed = await logs.listLogs();
      expect(listed[listed.length - 1].chainId).toBe('chain-z');
    });
  });

  describe('anchor_publications', () => {
    it('an explicit id below the last is refused', async () => {
      const before = await anchors.listAnchorPublications();
      expect(await refusal(...insertOf('anchor_publications', freshPublicationRow({ id: 0 })))).toMatch(BELOW_THE_LAST);
      expect(await anchors.listAnchorPublications()).toEqual(before);
    });

    it('an explicit id above the last that the sequence did not hand out is refused; the same row with no id is accepted and reads last', async () => {
      const last = await maxOf('anchor_publications', 'id');
      expect(await refusal(...insertOf('anchor_publications', freshPublicationRow({ id: last + 10 })))).toMatch(NOT_DRAWN);
      await pool.query(...insertOf('anchor_publications', freshPublicationRow()));
      expect((await anchors.listAnchorPublications()).map((p) => p.anchorSize)).toEqual([1, 2]);
    });
  });

  describe('an id the sequence handed out is never refused', () => {
    it('an insert that drew its seq, then waited while a higher seq committed, is accepted', async () => {
      // A trigger that sorts before the guard makes the insert of event
      // `waits` wait on an advisory lock after its seq is drawn. While it
      // waits, another registration draws the next seq and commits.
      const lockKey = 2026092701;
      await pool.query(`
        CREATE FUNCTION aaa_wait() RETURNS TRIGGER AS $$
        BEGIN
          IF NEW.event_id = 'waits' THEN PERFORM pg_advisory_xact_lock(${lockKey}); END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER aaa_wait_trigger BEFORE INSERT ON credential_events FOR EACH ROW EXECUTE FUNCTION aaa_wait();
      `);
      const holder = new Client({ connectionString: pgSchema.url });
      const waiter = new Client({ connectionString: pgSchema.url });
      await holder.connect();
      await waiter.connect();
      try {
        await holder.query('SELECT pg_advisory_lock($1)', [lockKey]);
        const waiting = waiter.query(
          ...insertOf('credential_events', plantedRegistration({ event_id: 'waits', credential_id: 'cred-5', public_key: GOODKEY })),
        );
        // Until the insert is blocked on the lock, its seq may not be drawn yet.
        for (let i = 0; i < 200; i++) {
          const blocked = await all("SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND objid = $1", [lockKey]);
          if (blocked.length > 0) break;
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
        await credentials.register(credential('cred-6', GOODKEY));
        await holder.query('SELECT pg_advisory_unlock($1)', [lockKey]);
        await waiting;
        const rows = await all("SELECT credential_id FROM credential_events WHERE credential_id IN ('cred-5', 'cred-6') ORDER BY seq");
        // The waiting insert drew its default seq first and was accepted:
        // the guard read its statement's snapshot, where the seq committed
        // while it waited is not visible. The row takes the seq the guard
        // draws after the wait, so it reads after that one.
        expect(rows.map((r) => r.credential_id)).toEqual(['cred-6', 'cred-5']);
      } finally {
        await holder.end();
        await waiter.end();
        await pool.query('DROP TRIGGER aaa_wait_trigger ON credential_events; DROP FUNCTION aaa_wait()');
      }
    });

    it('concurrent writers on every guarded table all go through', async () => {
      const writers = Array.from({ length: 12 }, (_, i) => i);
      await Promise.all(writers.map((i) => credentials.register(credential(`cred-c${i}`, GOODKEY))));
      await Promise.all(writers.map((i) => anchors.ensureStoreLog(`k${i}`)));
      expect((await credentials.list())).toHaveLength(2 + writers.length);
      expect((await logs.listLogs()).filter((l) => /^k\d+$/.test(l.kind))).toHaveLength(writers.length);
    });

    it('the store’s own writes to all four tables go through', async () => {
      await credentials.register(credential('cred-7', GOODKEY));
      await credentials.updateCounter('cred-7', 5);
      await credentials.updateCounter('cred-7', 1); // a counter regression is an event
      await adapter.store(makeEnvelope({ evidenceId: 'ev-other', sequenceNumber: 1 }), 'chain-other');
      await adapter.appendCustodyEntry('ev-2', {
        timestamp: '2026-09-27T12:00:00.000Z', actor: 'alice@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
      });
      await anchors.insertAnchorPublication({
        epochId: 3, anchorSize: 3, p: checkpointFor(anchorLog, 3).bodyDigest, kind: 'rfc3161/1', chain: null,
      });
      expect((await credentials.history('cred-7')).map((e) => e.type)).toEqual(['registered', 'counter_regressed']);
      expect((await adapter.listCustodyEntries('ev-2')).map((e) => e.action)).toEqual(['relinked', 'reviewed']);
      expect((await logs.getEvidenceLog('chain-other'))?.chainId).toBe('chain-other');
      expect((await anchors.listAnchorPublications()).map((p) => p.anchorSize)).toEqual([1, 3]);
    });
  });

  describe('the inserting session’s names do not stand in for the table, its sequence or the comparisons', () => {
    // A least-privileged INSERT role: it may read and insert every table and
    // draw from every sequence, and holds the TEMP that PUBLIC has on a
    // database by default. For the search_path case it may also create
    // objects in a schema of its own.
    const role = `backdated_id_${randomBytes(5).toString('hex')}`;
    const password = randomBytes(16).toString('hex');
    const own = `backdated_id_own_${randomBytes(5).toString('hex')}`;

    const asAdmin = async (sql: string): Promise<void> => {
      const client = new Client({ connectionString: pgSchema.url });
      await client.connect();
      try {
        await client.query(sql);
      } finally {
        await client.end();
      }
    };
    async function asRole(): Promise<Client> {
      const url = new URL(pgSchema.url);
      url.username = role;
      url.password = password;
      const client = new Client({ connectionString: url.toString() });
      await client.connect();
      return client;
    }

    beforeAll(() => asAdmin(
      `CREATE ROLE ${role} LOGIN PASSWORD '${password}';
       CREATE SCHEMA ${own};
       GRANT USAGE, CREATE ON SCHEMA ${own} TO ${role}`,
    ));
    beforeEach(() => asAdmin(
      `GRANT USAGE ON SCHEMA ${pgSchema.name} TO ${role};
       GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA ${pgSchema.name} TO ${role};
       GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${pgSchema.name} TO ${role}`,
    ));
    afterAll(() => asAdmin(`DROP SCHEMA ${own} CASCADE; DROP OWNED BY ${role}; DROP ROLE ${role}`));

    const rowAtZero = async (table: string, column: string): Promise<Row> => {
      const rows: Record<string, () => Promise<Row> | Row> = {
        credential_events: () => plantedRegistration(),
        custody_entries: nextCustodyRow,
        logs: () => freshLogRow(),
        anchor_publications: () => freshPublicationRow(),
      };
      return { [column]: 0, ...(await rows[table]()) };
    };

    it.each([
      ['credential_events', 'seq'],
      ['custody_entries', 'id'],
      ['logs', 'log_id'],
      ['anchor_publications', 'id'],
    ])('a temporary %s of the role’s own, whose sequence it set to 0, does not stand in for the table: a row at %s 0 is refused', async (table, column) => {
      const before = await snapshot(table, column);
      const row = await rowAtZero(table, column);
      const client = await asRole();
      try {
        // The role may write the row: written directly, the guard refuses it.
        await expect(client.query(...insertOf(table, row))).rejects.toThrow(BELOW_THE_LAST);
        // A temporary table of the same name is searched before the store's
        // schema, and its own sequence has handed this session 0.
        await client.query(
          `CREATE TEMP SEQUENCE shadow MINVALUE -10;
           CREATE TEMP TABLE ${table} (${column} BIGINT DEFAULT nextval('shadow'));
           ALTER SEQUENCE shadow OWNED BY ${table}.${column};
           SELECT setval('shadow', -1);
           SELECT nextval('shadow')`,
        );
        await expect(client.query(...insertOf(`${pgSchema.name}.${table}`, row))).rejects.toThrow(BELOW_THE_LAST);
      } finally {
        await client.end();
      }
      expect(await snapshot(table, column)).toEqual(before);
      expect((await credentials.getByCredentialId('cred-1'))?.publicKey).toBe(GOODKEY);
    });

    it('an operator and a currval of the role’s own, on a schema it puts ahead of pg_catalog, do not stand in for the real ones', async () => {
      const before = await snapshot('credential_events', 'seq');
      const client = await asRole();
      try {
        // `<` is never true, and currval is always 0: a guard that read
        // through the session's search_path would pass a registration at
        // seq 0 on both checks.
        await client.query(
          `CREATE FUNCTION ${own}.never_below(bigint, bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false';
           CREATE OPERATOR ${own}.< (LEFTARG = bigint, RIGHTARG = bigint, FUNCTION = ${own}.never_below);
           CREATE FUNCTION ${own}.currval(regclass) RETURNS bigint LANGUAGE sql AS 'SELECT 0::bigint';
           CREATE FUNCTION ${own}.currval(text) RETURNS bigint LANGUAGE sql AS 'SELECT 0::bigint';
           SET search_path = ${own}, pg_catalog, ${pgSchema.name}`,
        );
        await expect(client.query(...insertOf('credential_events', plantedRegistration({ seq: 0 })))).rejects.toThrow(BELOW_THE_LAST);
      } finally {
        await client.end();
      }
      expect(await snapshot('credential_events', 'seq')).toEqual(before);
      expect((await credentials.getByCredentialId('cred-1'))?.publicKey).toBe(GOODKEY);
    });

    it('the role’s own inserts, with no id, go through; a publication needs the store’s owner', async () => {
      const client = await asRole();
      try {
        await client.query(...insertOf('credential_events', plantedRegistration({ event_id: 'role', credential_id: 'cred-8', public_key: GOODKEY })));
        await client.query(...insertOf('custody_entries', await nextCustodyRow()));
        await client.query(...insertOf('logs', await freshLogRow()));
        // Every anchoring write needs the role that owns the store, whatever
        // its id: the owner's own insert with no id is above.
        await expect(client.query(...insertOf('anchor_publications', freshPublicationRow()))).rejects.toThrow(/\[tzun:anchoring_owner_required\]/);
      } finally {
        await client.end();
      }
      expect((await credentials.getByCredentialId('cred-8'))?.publicKey).toBe(GOODKEY);
      expect((await adapter.listCustodyEntries('ev-2')).map((e) => e.action)).toEqual(['relinked', 'reviewed']);
      const listed = await logs.listLogs();
      expect(listed[listed.length - 1].chainId).toBe('chain-z');
      expect((await anchors.listAnchorPublications()).map((p) => p.anchorSize)).toEqual([1]);
    });
  });

  describe('the guards are installed on open', () => {
    const installed = async (): Promise<string[]> =>
      (await all(
        `SELECT c.relname AS "table", t.tgname AS trigger
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
          WHERE c.relnamespace = current_schema()::regnamespace AND t.tgname = ANY($1::text[])`,
        [GUARDS.map((g) => g.trigger)],
      )).map((r) => `${r.table}.${r.trigger}`).sort();
    const expected = GUARDS.map((g) => `${g.table}.${g.trigger}`).sort();

    it('each once, however often the store is opened', async () => {
      const again = new PostgresStorageAdapter(pgSchema.url);
      await again.ensureTables();
      await again.close();
      expect(await installed()).toEqual(expected);
    });

    it('a store opened before they existed gets them the next time it is opened', async () => {
      for (const g of GUARDS) await pool.query(`DROP FUNCTION ${g.fn}() CASCADE`);
      expect(await installed()).toEqual([]);
      // Without them the key swap goes through (rolled back here).
      const client = new Client({ connectionString: pgSchema.url });
      await client.connect();
      try {
        await client.query('BEGIN');
        await client.query(...insertOf('credential_events', plantedRegistration({ seq: 0 })));
        expect((await client.query("SELECT public_key FROM credential_events WHERE credential_id = 'cred-1' ORDER BY seq LIMIT 1")).rows[0].public_key).toBe(MALLORYKEY);
        await client.query('ROLLBACK');
      } finally {
        await client.end();
      }

      const reopened = new PostgresStorageAdapter(pgSchema.url);
      await reopened.ensureTables();
      await reopened.close();
      expect(await installed()).toEqual(expected);
      expect(await refusal(...insertOf('credential_events', plantedRegistration({ seq: 0 })))).toMatch(BELOW_THE_LAST);
      expect((await credentials.getByCredentialId('cred-1'))?.publicKey).toBe(GOODKEY);
    });
  });
});
