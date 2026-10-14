/**
 * No Postgres trigger function of the SDK reads a table through
 * the names of the session that fires it.
 *
 * A trigger function runs with the search_path of the session whose statement
 * fired it. The guards that read tables are the custody ledger's verifier, the
 * guard on `envelopes` UPDATEs, the trigger that writes each record's
 * evidence-log leaf, and the guards on the log and anchor tables. A guard that
 * named its tables bare would read a temporary table of the same name, or one
 * in a schema the inserting role can create in and put first on its
 * search_path, and accept what it exists to refuse. On `custody_entries`, for
 * example, an empty temporary `custody_entries` would make a second genesis
 * entry for a record that already has one its "current tail".
 *
 * Every function runs with `search_path = pg_catalog, pg_temp` and names
 * every table through the schema of the table its trigger is on
 * (`TG_TABLE_SCHEMA`), as `postgresBackdatedIdGuard()` does. Each attack
 * below is a statement the guard refuses when a least-privileged role writes
 * it plainly. The role then shadows the tables the guard reads, once with
 * temporary tables and once with tables in a schema of its own that it puts
 * first on its search_path, puts the rows it wants read in them, and writes
 * the statement again: the guard refuses it again, and the store reads as it
 * did before. An entry_hash computed by a function in the role's schema is
 * refused the same way, and a store whose functions are the 0.5.0
 * definitions, which pin no search_path, gets the pinned ones the next time
 * it is opened.
 *
 * Runs when the Postgres legs do (tests/ts/helpers/postgres-test-db.ts), in a
 * schema of this file's own, with a role of its own.
 */
import { createHash, randomBytes } from 'node:crypto';
import { Client, Pool } from 'pg';
import { canonicalCustodyMetadata, computeCustodyEntryHash } from '@tzun/engine';
import type { EvidenceEnvelope } from '@tzun/engine';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { anchorStoreFor, logStoreFor, type AnchorStore, type LogRecord } from '../../src/storage/log-store';
import { makeEnvelope, makeRelink } from './storage-conformance/fixtures';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { restore050FunctionsPostgres } from './helpers/store-schema';

const pgSchema = pgSuiteSchema('search_path');
const describeLive = PG_TESTS_ENABLED ? describe : describe.skip;
/** The store's schema. */
const S = pgSchema.name;

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

const CHAIN = 'eip155:31337';
/** Enrolled, with an accounted transaction at nonce 7. */
const ENROLLED = `0x${'1'.repeat(40)}`;
/** Enrolled, then retired. */
const RETIRED = `0x${'2'.repeat(40)}`;
/** Never enrolled. */
const PLANTED = `0x${'3'.repeat(40)}`;
/** The identity the role's shadow `store_identity` claims. */
const EVIL_STORE_ID = 'e'.repeat(32);
const EVIL_DOMAIN = `evil/${EVIL_STORE_ID}`;

type Row = Record<string, unknown>;
type Statement = [string, unknown[]];

/** `INSERT INTO table (columns) VALUES ($1, ...)` for `row`, with `row`'s values in column order. */
function insertOf(table: string, row: Row): Statement {
  const columns = Object.keys(row);
  return [
    `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${columns.map((_, i) => `$${i + 1}`).join(', ')})`,
    columns.map((c) => row[c]),
  ];
}

/** A `log_checkpoints` row for `log` at `treeSize` that log_checkpoints_verify_insert accepts when the leaf is there. */
function checkpointRow(log: LogRecord, treeSize: number): Row {
  const root = hex(`root-${log.origin}-${treeSize}`);
  const body = `${log.origin}\n${treeSize}\n${Buffer.from(root, 'hex').toString('base64')}\n`;
  return {
    log_id: log.logId,
    tree_size: treeSize,
    root,
    body,
    body_digest: createHash('sha256').update(body).digest('hex'),
    compact_range: JSON.stringify([root]),
  };
}

/** How the role shadows a table. */
interface Shadow {
  /** What the role runs first. */
  prelude: string;
  /** The statement that creates the shadow of `table`. */
  create(table: string): string;
  /** The shadow of `table`, qualified. */
  ref(table: string): string;
}

/** One attack: a statement a guard refuses, and the tables that guard reads. */
interface Attack {
  /** What the statement tries. */
  what: string;
  /** The tables the role shadows. */
  shadows: string[];
  /** Rows the role puts in its shadows. */
  plant?: (ref: (table: string) => string) => Promise<Statement[]>;
  /** The statement, naming the store's table qualified. */
  statement: () => Promise<Statement>;
  refusal: RegExp;
  /** What must read the same after the refusals. */
  state: () => Promise<unknown>;
}

describeLive('Postgres trigger functions read the store, not the inserting session’s names', () => {
  jest.setTimeout(60_000);

  let adapter: PostgresStorageAdapter;
  let pool: Pool;
  let anchors: AnchorStore;
  let anchorLog: LogRecord;
  let evidenceLog: LogRecord;
  let domain: string;

  // A least-privileged role: it reads, inserts and updates the store's tables
  // and draws from its sequences, holds the TEMP that PUBLIC has on a database
  // by default, and may create in a schema of its own.
  const role = `search_path_${randomBytes(5).toString('hex')}`;
  const password = randomBytes(16).toString('hex');
  const own = `search_path_own_${randomBytes(5).toString('hex')}`;

  const SHADOWS: Record<'a temporary table' | 'a table in a schema the role puts first', Shadow> = {
    'a temporary table': {
      prelude: 'SELECT 1',
      create: (t) => `CREATE TEMP TABLE ${t} (LIKE ${S}.${t} INCLUDING ALL)`,
      ref: (t) => `pg_temp.${t}`,
    },
    'a table in a schema the role puts first': {
      prelude: `SET search_path = ${own}, ${S}`,
      create: (t) => `CREATE TABLE ${own}.${t} (LIKE ${S}.${t} INCLUDING ALL)`,
      ref: (t) => `${own}.${t}`,
    },
  };

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

  beforeAll(() => asAdmin(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`));
  afterAll(() => asAdmin(`DROP SCHEMA IF EXISTS ${own} CASCADE; DROP OWNED BY ${role}; DROP ROLE ${role}`));

  beforeEach(async () => {
    await pgSchema.empty();
    adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    pool = new Pool({ connectionString: pgSchema.url });
    anchors = anchorStoreFor(adapter)!;

    // Three records, and a relink of ev-2 that ledgers its first custody entry.
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

    evidenceLog = (await logStoreFor(adapter)!.getEvidenceLog('default'))!;
    // The anchor log: three leaves, checkpoints at sizes 1 to 3, a publication at size 1.
    anchorLog = await anchors.ensureStoreLog('anchors');
    await anchors.appendLogLeaves(anchorLog.logId, [0, 1, 2].map((i) => ({
      leafIndex: i, leafDigest: hex(`anchor-leaf-${i}`), sourceRef: `cp-${i}`,
    })));
    for (const size of [1, 2, 3]) {
      const row = checkpointRow(anchorLog, size);
      await anchors.insertLogCheckpoint({
        logId: anchorLog.logId, treeSize: size, root: row.root as string, body: row.body as string,
        bodyDigest: row.body_digest as string, compactRange: [row.root as string],
        prevAnchoredSize: null, consistencyProof: null, anchorLeafIndex: null, epochId: null,
      });
    }
    await anchors.insertAnchorPublication({
      epochId: 1, anchorSize: 1, p: checkpointRow(anchorLog, 1).body_digest as string, kind: 'evm-calldata/1', chain: CHAIN,
    });

    // Two wallets, one retired; an accounted transaction of the other at nonce 7.
    const identity = await logStoreFor(adapter)!.getStoreIdentity();
    domain = `${identity.ns}/${identity.storeId}`;
    await anchors.enrolAnchorWallet({ address: ENROLLED, chain: CHAIN, domain, nonceBase: 0 });
    await anchors.enrolAnchorWallet({ address: RETIRED, chain: CHAIN, domain, nonceBase: 0 });
    await anchors.retireAnchorWallet(RETIRED, CHAIN);
    await pool.query(...insertOf('anchor_wallet_txs', {
      address: ENROLLED, chain: CHAIN, nonce: 7, tx_hash: `0x${hex('sweep-7')}`, kind: 'sweep', raw_tx: '0xc0ffee',
    }));

    await asAdmin(
      `DROP SCHEMA IF EXISTS ${own} CASCADE;
       CREATE SCHEMA ${own};
       GRANT USAGE, CREATE ON SCHEMA ${own} TO ${role};
       GRANT USAGE ON SCHEMA ${S} TO ${role};
       GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ${S} TO ${role};
       GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${S} TO ${role}`,
    );
  });

  afterEach(async () => {
    await pool?.end();
    await adapter?.close();
  });

  const all = async (sql: string, params: unknown[] = []): Promise<Row[]> => (await pool.query(sql, params)).rows;
  const rowsOf = (table: string, order: string) => () => all(`SELECT * FROM ${table} ORDER BY ${order}`);

  const recordDigest = async (evidenceId: string): Promise<string> =>
    ((await all('SELECT envelope FROM envelopes WHERE evidence_id = $1', [evidenceId]))[0].envelope as EvidenceEnvelope)
      .integrity.canonicalDigest;
  const tail = async (): Promise<string> =>
    (await all("SELECT entry_hash FROM custody_entries WHERE evidence_id = 'ev-2' ORDER BY id DESC LIMIT 1"))[0]
      .entry_hash as string;

  /** A custody row for ev-2 whose entry_hash recomputes over `prev` and `digest`. */
  async function custodyRow(prev: string | null, digest?: string): Promise<Row> {
    const fields = {
      evidenceId: 'ev-2',
      canonicalDigest: digest ?? (await recordDigest('ev-2')),
      action: 'reviewed',
      actor: 'mallory@acme.example',
      timestamp: '2026-09-27T11:00:00.000Z',
      systemId: 'tzun-recovery',
    };
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
      prev_entry_hash: prev,
      entry_hash: computeCustodyEntryHash({ ...fields, prevEntryHash: prev, metadata: null }),
      recovery_id: null,
    };
  }
  const custodyRows = rowsOf('custody_entries', 'id');

  const evilIdentity = async (ref: (t: string) => string): Promise<Statement[]> => [
    insertOf(ref('store_identity'), { singleton: 1, store_id: EVIL_STORE_ID, ns: 'evil' }),
  ];

  const ATTACKS: Attack[] = [
    {
      what: 'custody_entries: a second genesis entry for a record whose ledger has one',
      shadows: ['custody_entries'],
      statement: async () => insertOf(`${S}.custody_entries`, await custodyRow(null)),
      refusal: /prev_entry_hash is not the record's current tail/,
      state: custodyRows,
    },
    {
      what: 'custody_entries: an entry bound to a digest the record does not carry',
      shadows: ['envelopes'],
      plant: async (ref) => [
        insertOf(ref('envelopes'), {
          evidence_id: 'ev-2',
          envelope: JSON.stringify({ integrity: { canonicalDigest: hex('forged') } }),
          captured_at: '2026-09-27T00:00:00Z',
          ai_system_id: 'forged',
          digest: 'forged',
        }),
      ],
      statement: async () => insertOf(`${S}.custody_entries`, await custodyRow(await tail(), hex('forged'))),
      refusal: /canonical_digest does not match the record/,
      state: custodyRows,
    },
    {
      what: 'envelopes: a mirrored custody entry whose entryHash no ledger row holds',
      shadows: ['custody_entries'],
      plant: async (ref) => [
        insertOf(ref('custody_entries'), {
          evidence_id: 'ev-2', canonical_digest: await recordDigest('ev-2'), action: 'reviewed', actor: 'mallory@acme.example',
          ts: '2026-09-27T11:00:00.000Z', system_id: 'tzun-recovery', entry_hash: hex('forged-entry'),
        }),
      ],
      statement: async () => [
        `UPDATE ${S}.envelopes SET envelope = jsonb_set(envelope, '{custodyChain}', (envelope->'custodyChain') || $1::jsonb)
          WHERE evidence_id = 'ev-2'`,
        [JSON.stringify([{
          timestamp: '2026-09-27T11:00:00.000Z', actor: 'mallory@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
          entryHash: hex('forged-entry'),
        }])],
      ],
      refusal: /entryHash with no custody_entries row/,
      state: rowsOf('envelopes', 'evidence_id'),
    },
    {
      what: 'envelopes: a record whose evidence-log leaf leaves a gap',
      shadows: ['log_leaves'],
      statement: async () => {
        const record = makeEnvelope({ evidenceId: 'ev-9', sequenceNumber: 9 });
        return insertOf(`${S}.envelopes`, {
          evidence_id: 'ev-9', envelope: JSON.stringify(record), captured_at: record.payload.capturedAt,
          ai_system_id: record.payload.aiSystemId, digest: record.integrity.canonicalDigest, chain_id: 'default',
        });
      },
      refusal: /\[tzun:log_gap\]/,
      state: async () => [await all('SELECT evidence_id FROM envelopes ORDER BY evidence_id'), await rowsOf('log_leaves', 'log_id, leaf_index')()],
    },
    {
      what: 'log_leaves: a leaf with no predecessor',
      shadows: ['log_leaves'],
      plant: async (ref) => [
        insertOf(ref('log_leaves'), { log_id: anchorLog.logId, leaf_index: 4, leaf_digest: hex('shadow-4'), source_ref: 'shadow-4', source: 'scheduler' }),
      ],
      statement: async () =>
        insertOf(`${S}.log_leaves`, { log_id: anchorLog.logId, leaf_index: 5, leaf_digest: hex('planted-5'), source_ref: 'planted-5', source: 'scheduler' }),
      refusal: /\[tzun:log_gap\]/,
      state: rowsOf('log_leaves', 'log_id, leaf_index'),
    },
    {
      // The record binding reads envelopes through the store's schema.
      what: 'log_leaves: an evidence leaf that copies no stored record',
      shadows: ['envelopes'],
      plant: async (ref) => {
        const phantom = makeEnvelope({ evidenceId: 'phantom', sequenceNumber: 4 });
        return [
          insertOf(ref('envelopes'), {
            evidence_id: 'phantom', envelope: JSON.stringify(phantom), captured_at: phantom.payload.capturedAt,
            ai_system_id: phantom.payload.aiSystemId, digest: phantom.integrity.canonicalDigest, chain_id: 'default',
          }),
        ];
      },
      statement: async () =>
        insertOf(`${S}.log_leaves`, {
          log_id: evidenceLog.logId, leaf_index: 3, leaf_digest: makeEnvelope({ evidenceId: 'phantom', sequenceNumber: 4 }).integrity.canonicalDigest,
          source_ref: 'phantom', source: 'capture',
        }),
      refusal: /\[tzun:leaf_without_record\]/,
      state: rowsOf('log_leaves', 'log_id, leaf_index'),
    },
    {
      what: 'logs: a log whose origin the store identity does not name',
      shadows: ['store_identity'],
      plant: evilIdentity,
      statement: async () => insertOf(`${S}.logs`, { origin: `${EVIL_DOMAIN}/planted`, kind: 'planted', chain_id: null }),
      refusal: /is not the one the store identity names for this log/,
      state: rowsOf('logs', 'log_id'),
    },
    {
      what: 'log_checkpoints: a checkpoint at a size the log has no leaf for',
      shadows: ['log_leaves'],
      plant: async (ref) => [
        insertOf(ref('log_leaves'), { log_id: anchorLog.logId, leaf_index: 9, leaf_digest: hex('shadow-9'), source_ref: 'shadow-9', source: 'scheduler' }),
      ],
      statement: async () => insertOf(`${S}.log_checkpoints`, checkpointRow(anchorLog, 10)),
      refusal: /has no leaf at tree_size - 1/,
      state: rowsOf('log_checkpoints', 'log_id, tree_size'),
    },
    {
      what: 'anchor_publications: a publication whose P is no stored checkpoint of the anchor log',
      shadows: ['log_checkpoints'],
      plant: async (ref) => [insertOf(ref('log_checkpoints'), checkpointRow(anchorLog, 7))],
      statement: async () =>
        insertOf(`${S}.anchor_publications`, {
          epoch_id: 7, anchor_size: 7, p: checkpointRow(anchorLog, 7).body_digest, kind: 'evm-calldata/1', state: 'prepared', chain: CHAIN,
        }),
      refusal: /P is not the digest of the anchor log's stored checkpoint at anchor_size/,
      state: rowsOf('anchor_publications', 'id'),
    },
    {
      what: 'anchor_publications: a nonce an accounted wallet transaction holds',
      shadows: ['anchor_wallet_txs'],
      statement: async () => [`UPDATE ${S}.anchor_publications SET from_address = $1, nonce = 7 WHERE epoch_id = 1`, [ENROLLED]],
      refusal: /an accounted wallet transaction holds the nonce/,
      state: rowsOf('anchor_publications', 'id'),
    },
    {
      what: 'anchor_lease: a lease for a domain that is not the store’s',
      shadows: ['store_identity'],
      plant: evilIdentity,
      statement: async () => insertOf(`${S}.anchor_lease`, { domain: EVIL_DOMAIN, holder: 'mallory', expires_at: '2099-01-01T00:00:00Z' }),
      refusal: /the domain is not the store's domain prefix/,
      state: rowsOf('anchor_lease', 'domain'),
    },
    {
      what: 'anchor_wallets: a wallet enrolled for a domain that is not the store’s',
      shadows: ['store_identity'],
      plant: evilIdentity,
      statement: async () => insertOf(`${S}.anchor_wallets`, { address: PLANTED, chain: CHAIN, domain: EVIL_DOMAIN, nonce_base: 0 }),
      refusal: /a wallet is enrolled for the store's own domain prefix/,
      state: rowsOf('anchor_wallets', 'address'),
    },
    {
      what: 'anchor_wallet_txs: a transaction of a retired wallet',
      shadows: ['anchor_wallets'],
      plant: async (ref) => [insertOf(ref('anchor_wallets'), { address: RETIRED, chain: CHAIN, domain, nonce_base: 0 })],
      statement: async () =>
        insertOf(`${S}.anchor_wallet_txs`, {
          address: RETIRED, chain: CHAIN, nonce: 0, tx_hash: `0x${hex('planted-sweep')}`, kind: 'sweep', raw_tx: '0xc0ffee',
        }),
      refusal: /the wallet is not enrolled and unretired/,
      state: rowsOf('anchor_wallet_txs', 'address, nonce'),
    },
  ];

  describe.each(Object.keys(SHADOWS) as Array<keyof typeof SHADOWS>)('shadowed with %s', (how) => {
    const shadow = SHADOWS[how];

    it.each(ATTACKS.map((a) => [a.what, a] as const))('%s is refused', async (_what, attack) => {
      const before = await attack.state();
      const client = await asRole();
      try {
        // The role may write the statement: written plainly, the guard refuses it.
        await expect(client.query(...(await attack.statement()))).rejects.toThrow(attack.refusal);
        await client.query(shadow.prelude);
        for (const table of attack.shadows) await client.query(shadow.create(table));
        for (const planted of (await attack.plant?.(shadow.ref)) ?? []) await client.query(...planted);
        await expect(client.query(...(await attack.statement()))).rejects.toThrow(attack.refusal);
      } finally {
        await client.end();
      }
      expect(await attack.state()).toEqual(before);
    });
  });

  it('custody_entries: an entry_hash computed by a function in a schema the role puts first is refused', async () => {
    const before = await custodyRows();
    const row = { ...(await custodyRow(await tail())), entry_hash: 'chosen-by-mallory' };
    const client = await asRole();
    try {
      await expect(client.query(...insertOf(`${S}.custody_entries`, row))).rejects.toThrow(/entry_hash does not recompute/);
      await client.query(
        `CREATE FUNCTION ${own}.custody_entries_compute_hash(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)
           RETURNS TEXT LANGUAGE sql AS $$ SELECT 'chosen-by-mallory'::text $$;
         SET search_path = ${own}, ${S}`,
      );
      await expect(client.query(...insertOf(`${S}.custody_entries`, row))).rejects.toThrow(/entry_hash does not recompute/);
    } finally {
      await client.end();
    }
    expect(await custodyRows()).toEqual(before);
  });

  describe('every function is installed with its search_path pinned', () => {
    const functions = async (): Promise<Row[]> =>
      all(
        `SELECT p.proname AS name, p.proconfig AS config, pg_get_functiondef(p.oid) AS definition
           FROM pg_proc p
          WHERE p.pronamespace = $1::regnamespace
          ORDER BY p.proname`,
        [S],
      );

    it('on a new store: every function of the store, the trigger functions and the custody hash', async () => {
      const fns = await functions();
      const called = await all(
        `SELECT DISTINCT p.proname AS name
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
          WHERE c.relnamespace = $1::regnamespace AND NOT t.tgisinternal`,
        [S],
      );
      // Every function a trigger on the store's tables calls is the store's own.
      expect(called.length).toBeGreaterThan(30);
      expect(called.map((f) => f.name).filter((name) => !fns.some((f) => f.name === name))).toEqual([]);
      expect(fns.filter((f) => f.name === 'custody_entries_compute_hash')).toHaveLength(1);
      expect(fns.filter((f) => f.name === 'custody_entries_length_prefix')).toEqual([]);
      expect(fns.filter((f) => JSON.stringify(f.config) !== JSON.stringify(['search_path=pg_catalog, pg_temp'])).map((f) => f.name)).toEqual([]);
    });

    it('each open installs the same definitions', async () => {
      const before = await functions();
      const again = new PostgresStorageAdapter(pgSchema.url);
      await again.ensureTables();
      await again.close();
      expect(await functions()).toEqual(before);
    });

    it('a store with the 0.5.0 functions takes the second genesis entry; the next open replaces its functions, and refuses it', async () => {
      const fresh = await functions();
      await restore050FunctionsPostgres(pool);
      const before = await custodyRows();
      const genesis = insertOf(`${S}.custody_entries`, await custodyRow(null));

      const client = await asRole();
      try {
        await client.query('BEGIN');
        await client.query(`CREATE TEMP TABLE custody_entries (LIKE ${S}.custody_entries INCLUDING ALL) ON COMMIT DROP`);
        await client.query(...genesis);
        // The record's ledger now has two genesis entries: it has forked.
        const roots = await client.query(`SELECT count(*)::int AS n FROM ${S}.custody_entries WHERE evidence_id = 'ev-2' AND prev_entry_hash IS NULL`);
        expect(roots.rows[0].n).toBe(2);
        await client.query('ROLLBACK');
      } finally {
        await client.end();
      }

      const reopened = new PostgresStorageAdapter(pgSchema.url);
      await reopened.ensureTables();
      await reopened.close();
      expect(await functions()).toEqual(fresh);

      const again = await asRole();
      try {
        await again.query(`CREATE TEMP TABLE custody_entries (LIKE ${S}.custody_entries INCLUDING ALL)`);
        await expect(again.query(...genesis)).rejects.toThrow(/prev_entry_hash is not the record's current tail/);
      } finally {
        await again.end();
      }
      expect(await custodyRows()).toEqual(before);
    });
  });
});
