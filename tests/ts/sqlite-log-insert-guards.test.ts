/**
 * On SQLite, neither an insert nor a rowid change replaces a
 * row of the evidence-log, anchoring and credential tables, and no row is
 * written ahead of the rows it follows.
 *
 * SQLite's REPLACE conflict resolution deletes the row an insert or an update
 * conflicts with. That delete fires a DELETE trigger only under
 * `recursive_triggers`, and no UPDATE trigger fires at all.
 * sqlite-insert-guards.test.ts covers the seven tables of sqlite.ts; this
 * file covers the rest of the append-only family, following the same pattern:
 *
 *   - `<table>_block_replace`, BEFORE INSERT and so before conflict handling,
 *     refuses an insert naming a key a row already holds, whatever its
 *     conflict clause: on `store_identity` the singleton; on `logs` log_id,
 *     origin, a chain's evidence log and a per-store kind; on `log_checkpoints`
 *     (log_id, tree_size), body_digest and the rowid; on
 *     `anchor_publications` id, (kind, anchor_size) and a held sender and
 *     nonce; on `anchor_wallets` (address, chain) and the rowid; on
 *     `anchor_wallet_txs` (address, chain, nonce), tx_hash and the rowid; on
 *     `credential_events` seq and event_id. On `log_leaves` it refuses a
 *     rowid a leaf holds: `log_leaves_verify_insert` already refuses a taken
 *     position, source or digest, with the messages the adapters map.
 *   - `<table>_block_negative_rowid`, AFTER INSERT, refuses a row at a
 *     negative rowid, which every later insert would collide with.
 *   - `<table>_block_rowid_change` on the tables whose UPDATE trigger lets
 *     some updates through and a rowid change with them: `log_checkpoints`,
 *     `anchor_lease`, `anchor_wallets`. On `anchor_publications` the rowid is
 *     `id`, which its UPDATE trigger already fixes; the others refuse every
 *     UPDATE.
 *   - `anchor_publications_block_nonce_replace`: UPDATE OR REPLACE that gives
 *     a publication a sender and nonce another publication holds would delete
 *     that publication through the nonce index.
 *   - `logs_block_backdated_id`, `anchor_publications_block_backdated_id`
 *     and `credential_events_block_backdated_seq` refuse a row written at an
 *     explicit id below the table's last one. These tables are read in id
 *     order; a credential's first registration is the one that counts, so a
 *     registration planted at seq 0 would put another key on the credential
 *     without replacing a row.
 *
 * Every attack is a raw statement on the adapter's own connection, the way an
 * insider with the file open would issue it.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createHash } from 'crypto';
import Database from 'better-sqlite3';
import { Wallet, keccak256, type HDNodeWallet } from 'ethers';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import {
  ANCHOR_LEASE_HOLDER_PREFIX,
  anchorStoreFor,
  evidenceLogOrigin,
  logStoreFor,
  type AnchorPublication,
  type AnchorStore,
  type LogRecord,
  type LogStore,
  type NewLogCheckpoint,
} from '../../src/storage/log-store';

/** Lease holders as a scheduler names them: `tzun-anchor/2:<holder id>`. */
const HOLDER_A = `${ANCHOR_LEASE_HOLDER_PREFIX}holder-a`;
const HOLDER_B = `${ANCHOR_LEASE_HOLDER_PREFIX}holder-b`;
import type { AsyncCredentialStore, StoredCredential } from '../../src/attestation/credential-store';
import { makeEnvelope } from './storage-conformance/fixtures';

type Db = import('better-sqlite3').Database;
type Row = Record<string, unknown>;

/** The message a raw statement was refused with (realm-independent; see custody-trail-hashed-and-atomic.test.ts). */
function refusal(run: () => unknown): string {
  try {
    run();
  } catch (err) {
    const message = (err as { message?: unknown } | null)?.message;
    return typeof message === 'string' ? message : String(err);
  }
  throw new Error('expected the statement to be refused, but it went through');
}

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

const GUARDED = /\[tzun:duplicate_record\] .* \(INSERT over an existing row refused\)/;
const ROWID_FROZEN = /rowid is immutable/;
const NEGATIVE_ROWID = /rowid cannot be negative/;
const BACKDATED = /must be above every existing/;
const NONCE_HELD = /\[tzun:duplicate_record\] anchor_publications: another publication that is not superseded holds this sender and nonce/;
const WRITTEN_ONCE = /a leaf is written once/;
const DUPLICATE_LEAF = /\[tzun:duplicate_leaf\]/;
const UPDATE_REFUSED = /UPDATE refused|cannot be rewritten/;

const CHAIN = 'eip155:31337';
const SENDER = '0x' + '1'.repeat(40);
const GOODKEY = 'GOODKEY';
const MALLORYKEY = 'MALLORYKEY';

/** The ways an UPDATE can move a row to another rowid. UPDATE OR REPLACE onto a held rowid deletes that row. */
const ROWID_UPDATES = ['UPDATE', 'UPDATE OR REPLACE', 'UPDATE OR IGNORE', 'UPDATE OR FAIL', 'UPDATE OR ABORT'] as const;

/** The two conflict clauses that replace a row. */
const REPLACING = ['INSERT OR REPLACE INTO', 'REPLACE INTO'] as const;

const placeholders = (columns: readonly string[]) => columns.map(() => '?').join(', ');

/**
 * A row's insert-time cell (`created_at`, `logged_at`): the statement's own
 * time, which the anchoring tables require.
 */
const NOW = Symbol('the statement\'s own time');
const SQLITE_NOW_SQL = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";

/**
 * Every way to spell an INSERT that meets an existing key. The first three
 * would replace the row (the INSERT ... SELECT form too); the rest would fail
 * on the key or be skipped, or, for the upsert, update the row in place. The
 * guard refuses each of them, so no conflict clause is a way past it.
 */
const EVERY_CLAUSE: Array<[string, (table: string, columns: string[]) => string]> = [
  ['INSERT OR REPLACE', (t, c) => `INSERT OR REPLACE INTO ${t} (${c.join(', ')}) VALUES (${placeholders(c)})`],
  ['REPLACE INTO', (t, c) => `REPLACE INTO ${t} (${c.join(', ')}) VALUES (${placeholders(c)})`],
  ['INSERT OR REPLACE ... SELECT', (t, c) => `INSERT OR REPLACE INTO ${t} (${c.join(', ')}) SELECT ${placeholders(c)}`],
  ['INSERT OR IGNORE', (t, c) => `INSERT OR IGNORE INTO ${t} (${c.join(', ')}) VALUES (${placeholders(c)})`],
  ['INSERT OR FAIL', (t, c) => `INSERT OR FAIL INTO ${t} (${c.join(', ')}) VALUES (${placeholders(c)})`],
  ['INSERT OR ABORT', (t, c) => `INSERT OR ABORT INTO ${t} (${c.join(', ')}) VALUES (${placeholders(c)})`],
  ['plain INSERT', (t, c) => `INSERT INTO ${t} (${c.join(', ')}) VALUES (${placeholders(c)})`],
  ['ON CONFLICT DO NOTHING', (t, c) => `INSERT INTO ${t} (${c.join(', ')}) VALUES (${placeholders(c)}) ON CONFLICT DO NOTHING`],
  // The upsert: its DO UPDATE would rewrite the row it conflicts with.
  ['ON CONFLICT DO UPDATE', (t, c) =>
    `INSERT INTO ${t} (${c.join(', ')}) VALUES (${placeholders(c)}) ON CONFLICT DO UPDATE SET ${c.map((x) => `${x} = excluded.${x}`).join(', ')}`],
];

function checkpointFor(log: LogRecord, treeSize: number, label = 'root'): NewLogCheckpoint {
  const root = hex(`${label}-${log.origin}-${treeSize}`);
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

/** The row a raw INSERT writes for `cp`, column by column. */
function checkpointRow(cp: NewLogCheckpoint): Row {
  return {
    log_id: cp.logId,
    tree_size: cp.treeSize,
    root: cp.root,
    body: cp.body,
    body_digest: cp.bodyDigest,
    compact_range: JSON.stringify(cp.compactRange),
    prev_anchored_size: null,
    consistency_proof: null,
    anchor_leaf_index: null,
    epoch_id: null,
    signatures: '[]',
    created_at: '2026-09-27T12:00:00.000Z',
  };
}

const attempt = (n: number) => ({
  txHash: `0x${hex(`tx-${n}`)}`,
  rawTx: `0x02f8${hex(`raw-${n}`)}`,
  maxFeePerGas: '2000000000',
  maxPriorityFeePerGas: '1000000',
  sentAt: '2026-09-27T10:00:00.000Z',
  broadcast: 'accepted' as const,
});

const credential = (credentialId: string, publicKey: string): StoredCredential => ({
  credentialId,
  publicKey,
  userId: 'jane@acme.example',
  algorithm: 'ES256',
  counter: 0,
  status: 'active',
  registeredAt: '2026-03-22T10:00:00.000Z',
});

async function signedTx(signer: HDNodeWallet, nonce: number): Promise<{ rawTx: string; txHash: string }> {
  const rawTx = (
    await signer.signTransaction({
      type: 2, chainId: 31337n, nonce, to: signer.address, value: 0n, data: '0x',
      gasLimit: 21_000n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n,
    })
  ).toLowerCase();
  return { rawTx, txHash: keccak256(rawTx) };
}

describe('SQLite: an insert never replaces a row of the evidence-log, anchoring and credential tables', () => {
  jest.setTimeout(30_000);
  const w1 = Wallet.createRandom();
  const w2 = Wallet.createRandom();
  const w3 = Wallet.createRandom();
  const addr = (w: HDNodeWallet) => w.address.toLowerCase();

  let dir: string;
  let dbPath: string;
  let adapter: SqliteStorageAdapter;
  let db: Db;
  let logs: LogStore;
  let anchors: AnchorStore;
  let credentials: AsyncCredentialStore;
  let evidenceLog: LogRecord;
  let anchorLog: LogRecord;
  let domain: string;
  let finalized: AnchorPublication;
  let prepared: AnchorPublication;

  async function open(): Promise<void> {
    adapter = new SqliteStorageAdapter(dbPath);
    db = (adapter as unknown as { db: Db }).db;
    logs = logStoreFor(adapter)!;
    anchors = anchorStoreFor(adapter)!;
    credentials = adapter.credentialStore();
  }

  beforeEach(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-'));
    dbPath = path.join(dir, 'evidence.db');
    await open();

    // Three records: the default chain's evidence log, leaves 0..2.
    for (const n of [1, 2, 3]) await adapter.store(makeEnvelope({ evidenceId: `ev-${n}`, sequenceNumber: n }));
    evidenceLog = (await logs.getEvidenceLog('default'))!;
    const identity = await logs.getStoreIdentity();
    domain = `${identity.ns}/${identity.storeId}`;

    // The anchor log: three leaves, checkpoints at sizes 1 and 2.
    anchorLog = await anchors.ensureStoreLog('anchors');
    await anchors.appendLogLeaves(anchorLog.logId, [0, 1, 2].map((i) => ({
      leafIndex: i, leafDigest: hex(`anchor-leaf-${i}`), sourceRef: `cp-${i}`,
    })));
    await anchors.insertLogCheckpoint(checkpointFor(anchorLog, 1));
    await anchors.insertLogCheckpoint(checkpointFor(anchorLog, 2));

    // A finalized publication at anchor size 1, holding SENDER's nonce 1, and
    // a prepared one at anchor size 2.
    const p1 = (await anchors.getLogCheckpoint(anchorLog.logId, 1))!.bodyDigest;
    const p2 = (await anchors.getLogCheckpoint(anchorLog.logId, 2))!.bodyDigest;
    const a = await anchors.insertAnchorPublication({ epochId: 1, anchorSize: 1, p: p1, kind: 'evm-calldata/1', chain: CHAIN });
    await anchors.updateAnchorPublication(a.id, { state: 'submitted', fromAddress: SENDER, nonce: 1, attempts: [attempt(1)] });
    await anchors.updateAnchorPublication(a.id, {
      state: 'included', minedTxHash: attempt(1).txHash, blockNumber: 100, blockHash: `0x${hex('block-100')}`,
    });
    finalized = await anchors.updateAnchorPublication(a.id, { state: 'finalized' });
    prepared = await anchors.insertAnchorPublication({ epochId: 2, anchorSize: 2, p: p2, kind: 'evm-calldata/1', chain: CHAIN });

    await anchors.acquireAnchorLease(domain, HOLDER_A, 60_000);

    // Two wallets; w1 has accounted its nonce 5.
    await anchors.enrolAnchorWallet({ address: addr(w1), chain: CHAIN, domain, nonceBase: 5 });
    await anchors.enrolAnchorWallet({ address: addr(w2), chain: CHAIN, domain, nonceBase: 0 });
    await anchors.insertAnchorWalletTx({ address: addr(w1), chain: CHAIN, nonce: 5, kind: 'sweep', ...(await signedTx(w1, 5)) });

    // Two credentials; the second is revoked.
    await credentials.register(credential('cred-1', GOODKEY));
    await credentials.register(credential('cred-2', GOODKEY));
    await credentials.revoke('cred-2', { reason: 'lost' });
  });

  afterEach(async () => {
    await adapter.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const all = (sql: string, ...params: unknown[]) => db.prepare(sql).all(...params) as Row[];
  const one = (sql: string, ...params: unknown[]) => db.prepare(sql).get(...params) as Row;
  /** Every row of `table` with its rowid, in rowid order: what a refused statement must leave exactly as it was. */
  const snapshot = (table: string) => all(`SELECT rowid AS _rowid, * FROM ${table} ORDER BY rowid`);
  /** Run `sql` with `row`'s values in its column order. */
  const insert = (sql: (table: string, columns: string[]) => string, table: string, row: Row) => () => {
    const columns = Object.keys(row);
    let i = -1;
    // Each column's value is one `?`, in column order; a NOW cell is the expression itself.
    const text = sql(table, columns).replace(/\?/g, () => {
      i += 1;
      return row[columns[i]] === NOW ? SQLITE_NOW_SQL : '?';
    });
    return db.prepare(text).run(...columns.filter((c) => row[c] !== NOW).map((c) => row[c]));
  };
  const verbInsert = (verb: string) => (table: string, columns: string[]) =>
    `${verb} ${table} (${columns.join(', ')}) VALUES (${placeholders(columns)})`;

  /** An evidence log for a chain that has none: a `logs` row logs_verify_insert accepts. */
  async function freshLogRow(chainId: string, logId?: number): Promise<Row> {
    const identity = await logs.getStoreIdentity();
    return {
      ...(logId === undefined ? {} : { log_id: logId }),
      origin: evidenceLogOrigin(identity.ns, identity.storeId, chainId),
      kind: 'evidence',
      chain_id: chainId,
      created_at: '2026-09-27T12:00:00.000Z',
    };
  }

  /** A prepared publication anchor_publications_verify_insert accepts. */
  function freshPublicationRow(kind: 'evm-calldata/1' | 'rfc3161/1', anchorSize: number, id?: number): Row {
    return {
      ...(id === undefined ? {} : { id }),
      epoch_id: 9,
      anchor_size: anchorSize,
      p: one('SELECT body_digest FROM log_checkpoints WHERE log_id = ? AND tree_size = ?', anchorLog.logId, anchorSize).body_digest,
      kind,
      state: 'prepared',
      forced: 0,
      chain: kind === 'evm-calldata/1' ? CHAIN : null,
      created_at: NOW,
      updated_at: NOW,
    };
  }

  /** A wallet transaction anchor_wallet_txs_verify_insert accepts (its hash is not checked in SQL). */
  const txRow = (nonce: number, label: string, rowid?: number): Row => ({
    ...(rowid === undefined ? {} : { rowid }),
    address: addr(w1),
    chain: CHAIN,
    nonce,
    tx_hash: `0x${hex(label)}`,
    kind: 'handover',
    raw_tx: `0x02${hex(`raw-${label}`)}`,
    created_at: '2026-09-27T12:00:00.000Z',
  });

  const eventRow = (overrides: Row): Row => ({
    event_id: 'e-mallory',
    credential_id: 'cred-1',
    event_type: 'registered',
    occurred_at: '2026-01-01T00:00:00.000Z',
    recorded_at: '2026-01-01T00:00:00.000Z',
    user_id: 'mallory@acme.example',
    public_key: MALLORYKEY,
    algorithm: 'ES256',
    reason: null,
    ...overrides,
  });

  describe('store_identity', () => {
    it.each(EVERY_CLAUSE)('%s cannot rewrite the store identity', (_clause, sql) => {
      const before = snapshot('store_identity');
      const row = { ...one('SELECT * FROM store_identity'), store_id: 'f'.repeat(32) };
      expect(refusal(insert(sql, 'store_identity', row))).toMatch(GUARDED);
      expect(snapshot('store_identity')).toEqual(before);
    });
  });

  describe('logs', () => {
    it.each(EVERY_CLAUSE)('%s over an existing log is refused by the guard', (_clause, sql) => {
      const before = snapshot('logs');
      expect(refusal(insert(sql, 'logs', one('SELECT * FROM logs WHERE log_id = ?', evidenceLog.logId)))).toMatch(GUARDED);
      expect(snapshot('logs')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot put another log at an evidence log’s log_id, under its leaves', async (verb) => {
      // The leaves keep their log_id, so the foreign key holds: they would
      // now belong to chain-z's log.
      const before = snapshot('logs');
      expect(refusal(insert(verbInsert(verb), 'logs', await freshLogRow('chain-z', evidenceLog.logId)))).toMatch(GUARDED);
      expect(snapshot('logs')).toEqual(before);
      expect((await logs.getEvidenceLog('default'))!.logId).toBe(evidenceLog.logId);
    });

    it.each(REPLACING)('%s cannot move an evidence log to a new log_id by repeating its origin', async (verb) => {
      const before = snapshot('logs');
      const row = { ...one('SELECT * FROM logs WHERE log_id = ?', evidenceLog.logId), log_id: 99 };
      expect(refusal(insert(verbInsert(verb), 'logs', row))).toMatch(GUARDED);
      expect(snapshot('logs')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot move a per-store log to a new log_id', (verb) => {
      const before = snapshot('logs');
      const row = { ...one('SELECT * FROM logs WHERE log_id = ?', anchorLog.logId), log_id: 99 };
      expect(refusal(insert(verbInsert(verb), 'logs', row))).toMatch(GUARDED);
      expect(snapshot('logs')).toEqual(before);
    });

    it('an explicit log_id below the last is refused, and one above it is accepted', async () => {
      const before = snapshot('logs');
      expect(refusal(insert(verbInsert('INSERT INTO'), 'logs', await freshLogRow('chain-z', 0)))).toMatch(BACKDATED);
      expect(snapshot('logs')).toEqual(before);
      insert(verbInsert('INSERT INTO'), 'logs', await freshLogRow('chain-z', 50))();
      expect((await logs.listLogs()).map((l) => l.logId)).toEqual([evidenceLog.logId, anchorLog.logId, 50]);
    });
  });

  describe('log_leaves', () => {
    const leafRow = (overrides: Row = {}): Row => ({
      log_id: evidenceLog.logId,
      leaf_index: 3,
      leaf_digest: hex('ghost'),
      source_ref: 'ev-ghost',
      source: 'capture',
      logged_at: NOW,
      ...overrides,
    });

    it.each(REPLACING)('%s cannot erase leaf 0 by naming its rowid', async (verb) => {
      // Position 3 is free and follows leaf 2, and the source and digest are
      // new, so log_leaves_verify_insert accepts the row; REPLACE would then
      // delete the leaf at rowid 1.
      const before = snapshot('log_leaves');
      const leaf0 = one('SELECT rowid AS _rowid FROM log_leaves WHERE log_id = ? AND leaf_index = 0', evidenceLog.logId);
      expect(refusal(insert(verbInsert(verb), 'log_leaves', { rowid: leaf0._rowid, ...leafRow() }))).toMatch(GUARDED);
      expect(snapshot('log_leaves')).toEqual(before);
      expect((await logs.listLogLeaves(evidenceLog.logId, 0, 3)).map((l) => l.sourceRef)).toEqual(['ev-1', 'ev-2', 'ev-3']);
    });

    it.each(REPLACING)('%s cannot erase another log’s leaf by naming its rowid', (verb) => {
      const before = snapshot('log_leaves');
      const victim = one('SELECT rowid AS _rowid FROM log_leaves WHERE log_id = ? AND leaf_index = 0', anchorLog.logId);
      expect(refusal(insert(verbInsert(verb), 'log_leaves', { rowid: victim._rowid, ...leafRow() }))).toMatch(GUARDED);
      expect(snapshot('log_leaves')).toEqual(before);
    });

    // log_leaves_verify_insert refuses a taken position, source or digest,
    // with the messages the adapters translate (EvidenceLogRefusalError).
    it.each(EVERY_CLAUSE)('%s at a taken position is refused by log_leaves_verify_insert: a leaf is written once', (_clause, sql) => {
      const before = snapshot('log_leaves');
      const row = one('SELECT * FROM log_leaves WHERE log_id = ? AND leaf_index = 1', evidenceLog.logId);
      expect(refusal(insert(sql, 'log_leaves', { ...row, leaf_digest: hex('rewritten'), source_ref: 'ev-rewritten' })))
        .toMatch(WRITTEN_ONCE);
      expect(snapshot('log_leaves')).toEqual(before);
    });

    it.each(REPLACING)('%s of a repeated source or digest at a free position is refused by log_leaves_verify_insert', (verb) => {
      const before = snapshot('log_leaves');
      expect(refusal(insert(verbInsert(verb), 'log_leaves', leafRow({ source_ref: 'ev-1' })))).toMatch(DUPLICATE_LEAF);
      expect(refusal(insert(verbInsert(verb), 'log_leaves', leafRow({ leaf_digest: hex('ev-1') })))).toMatch(DUPLICATE_LEAF);
      expect(snapshot('log_leaves')).toEqual(before);
    });
  });

  describe('log_checkpoints', () => {
    it.each(EVERY_CLAUSE)('%s cannot rewrite a checkpoint at its size', (_clause, sql) => {
      const before = snapshot('log_checkpoints');
      const rewritten = checkpointRow(checkpointFor(anchorLog, 1, 'forged'));
      expect(refusal(insert(sql, 'log_checkpoints', rewritten))).toMatch(GUARDED);
      expect(snapshot('log_checkpoints')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot delete a checkpoint by repeating its body_digest at another size', (verb) => {
      const before = snapshot('log_checkpoints');
      const cp1 = one('SELECT body_digest FROM log_checkpoints WHERE log_id = ? AND tree_size = 1', anchorLog.logId);
      const row = { ...checkpointRow(checkpointFor(anchorLog, 3)), body_digest: cp1.body_digest };
      expect(refusal(insert(verbInsert(verb), 'log_checkpoints', row))).toMatch(GUARDED);
      expect(snapshot('log_checkpoints')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot delete a checkpoint by naming its rowid', (verb) => {
      const before = snapshot('log_checkpoints');
      const victim = one('SELECT rowid AS _rowid FROM log_checkpoints WHERE log_id = ? AND tree_size = 1', anchorLog.logId);
      const row = { rowid: victim._rowid, ...checkpointRow(checkpointFor(anchorLog, 3)) };
      expect(refusal(insert(verbInsert(verb), 'log_checkpoints', row))).toMatch(GUARDED);
      expect(snapshot('log_checkpoints')).toEqual(before);
    });

    it.each(ROWID_UPDATES)('%s cannot move a checkpoint’s rowid, onto another checkpoint or a free one', (verb) => {
      // log_checkpoints_guard_update lets signatures be appended, so a rowid
      // change needs its own guard: UPDATE OR REPLACE onto the size-1 row
      // would delete that checkpoint.
      const before = snapshot('log_checkpoints');
      const [cp1, cp2] = before;
      expect(refusal(() => db.prepare(`${verb} log_checkpoints SET rowid = ? WHERE rowid = ?`).run(cp1._rowid, cp2._rowid)))
        .toMatch(ROWID_FROZEN);
      expect(refusal(() => db.prepare(`${verb} log_checkpoints SET rowid = 999999 WHERE rowid = ?`).run(cp1._rowid)))
        .toMatch(ROWID_FROZEN);
      expect(snapshot('log_checkpoints')).toEqual(before);
    });
  });

  describe('anchor_publications', () => {
    it.each(REPLACING)('%s cannot replace a finalized publication with a fresh prepared one', async (verb) => {
      const before = snapshot('anchor_publications');
      expect(refusal(insert(verbInsert(verb), 'anchor_publications', freshPublicationRow('evm-calldata/1', 1)))).toMatch(GUARDED);
      expect(snapshot('anchor_publications')).toEqual(before);
      expect((await anchors.getAnchorPublication(finalized.id))!.state).toBe('finalized');
    });

    it.each(EVERY_CLAUSE)('%s over an existing id and anchor size is refused by the guard', (_clause, sql) => {
      const before = snapshot('anchor_publications');
      expect(refusal(insert(sql, 'anchor_publications', freshPublicationRow('evm-calldata/1', 1, finalized.id)))).toMatch(GUARDED);
      expect(snapshot('anchor_publications')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot delete a publication by naming its id', async (verb) => {
      const before = snapshot('anchor_publications');
      expect(refusal(insert(verbInsert(verb), 'anchor_publications', freshPublicationRow('rfc3161/1', 1, finalized.id)))).toMatch(GUARDED);
      expect(snapshot('anchor_publications')).toEqual(before);
    });

    it.each(['UPDATE', 'UPDATE OR REPLACE', 'UPDATE OR IGNORE'])(
      '%s cannot give a publication the sender and nonce a finalized one holds',
      async (verb) => {
        // The nonce index is unique among publications that are not
        // superseded: UPDATE OR REPLACE onto a held nonce would delete the
        // finalized publication, and fire no DELETE trigger.
        const before = snapshot('anchor_publications');
        expect(refusal(() => db.prepare(`${verb} anchor_publications SET from_address = ?, nonce = 1 WHERE id = ?`)
          .run(SENDER, prepared.id))).toMatch(NONCE_HELD);
        expect(snapshot('anchor_publications')).toEqual(before);
        expect((await anchors.getAnchorPublication(finalized.id))!.state).toBe('finalized');
      },
    );

    it('a nonce is taken again once the publication that held it is superseded', async () => {
      const sender = '0x' + '2'.repeat(40);
      await anchors.updateAnchorPublication(prepared.id, {
        state: 'submitted', fromAddress: sender, nonce: 7, attempts: [{ ...attempt(2), broadcast: 'rejected' }],
      });
      await anchors.updateAnchorPublication(prepared.id, { state: 'superseded' });
      await anchors.insertLogCheckpoint(checkpointFor(anchorLog, 3));
      const next = await anchors.insertAnchorPublication({
        epochId: 3, anchorSize: 3, p: (await anchors.getLogCheckpoint(anchorLog.logId, 3))!.bodyDigest, kind: 'evm-calldata/1', chain: CHAIN,
      });
      const took = await anchors.updateAnchorPublication(next.id, { state: 'submitted', fromAddress: sender, nonce: 7, attempts: [attempt(3)] });
      expect(took).toMatchObject({ state: 'submitted', nonce: 7 });
    });

    // The rowid is `id`, which anchor_publications_guard_update already holds fixed.
    it.each(ROWID_UPDATES)('%s cannot move a publication’s id', (verb) => {
      const idFixed = /id, epoch, anchor size, P, kind, chain and created_at are fixed/;
      const before = snapshot('anchor_publications');
      expect(refusal(() => db.prepare(`${verb} anchor_publications SET rowid = ? WHERE id = ?`).run(finalized.id, prepared.id)))
        .toMatch(idFixed);
      expect(refusal(() => db.prepare(`${verb} anchor_publications SET rowid = 999999 WHERE id = ?`).run(finalized.id)))
        .toMatch(idFixed);
      expect(snapshot('anchor_publications')).toEqual(before);
    });

    it('an explicit id below the last is refused, and one above it is accepted', async () => {
      const before = snapshot('anchor_publications');
      expect(refusal(insert(verbInsert('INSERT INTO'), 'anchor_publications', freshPublicationRow('rfc3161/1', 1, 0)))).toMatch(BACKDATED);
      expect(snapshot('anchor_publications')).toEqual(before);
      insert(verbInsert('INSERT INTO'), 'anchor_publications', freshPublicationRow('rfc3161/1', 1, 50))();
      expect((await anchors.listAnchorPublications()).map((p) => p.id)).toEqual([finalized.id, prepared.id, 50]);
    });
  });

  describe('anchor_lease', () => {
    it.each(ROWID_UPDATES)('%s cannot move the lease’s rowid', (verb) => {
      const before = snapshot('anchor_lease');
      expect(refusal(() => db.prepare(`${verb} anchor_lease SET rowid = 999999 WHERE domain = ?`).run(domain))).toMatch(ROWID_FROZEN);
      expect(snapshot('anchor_lease')).toEqual(before);
    });

    it('the lease is still taken, renewed, released and taken again through its upsert', async () => {
      expect((await anchors.acquireAnchorLease(domain, HOLDER_B, 60_000)).holder).toBe(HOLDER_A);
      expect((await anchors.acquireAnchorLease(domain, HOLDER_A, 120_000)).holder).toBe(HOLDER_A);
      await anchors.releaseAnchorLease(domain, HOLDER_A);
      expect((await anchors.acquireAnchorLease(domain, HOLDER_B, 60_000)).holder).toBe(HOLDER_B);
    });
  });

  describe('anchor_wallets', () => {
    const walletRow = (w: HDNodeWallet, overrides: Row = {}): Row => ({
      address: addr(w), chain: CHAIN, domain, nonce_base: 0, enrolled_at: '2026-09-27T12:00:00.000Z', retired_at: null, ...overrides,
    });

    it.each(REPLACING)('%s cannot bring a retired wallet back, with another nonce base', async (verb) => {
      await anchors.retireAnchorWallet(addr(w2), CHAIN);
      const before = snapshot('anchor_wallets');
      expect(refusal(insert(verbInsert(verb), 'anchor_wallets', walletRow(w2, { nonce_base: 99 })))).toMatch(GUARDED);
      expect(snapshot('anchor_wallets')).toEqual(before);
      expect((await anchors.getAnchorWallet(addr(w2), CHAIN))!.retiredAt).not.toBeNull();
    });

    it.each(EVERY_CLAUSE)('%s over an enrolled wallet is refused by the guard', (_clause, sql) => {
      const before = snapshot('anchor_wallets');
      expect(refusal(insert(sql, 'anchor_wallets', walletRow(w2, { nonce_base: 99 })))).toMatch(GUARDED);
      expect(snapshot('anchor_wallets')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot delete an enrolment by naming its rowid', (verb) => {
      const before = snapshot('anchor_wallets');
      const victim = one('SELECT rowid AS _rowid FROM anchor_wallets WHERE address = ?', addr(w2));
      expect(refusal(insert(verbInsert(verb), 'anchor_wallets', { rowid: victim._rowid, ...walletRow(w3) }))).toMatch(GUARDED);
      expect(snapshot('anchor_wallets')).toEqual(before);
    });

    it.each(ROWID_UPDATES)('%s cannot move an enrolment’s rowid, onto another enrolment or a free one', (verb) => {
      const before = snapshot('anchor_wallets');
      const [first, second] = before;
      expect(refusal(() => db.prepare(`${verb} anchor_wallets SET rowid = ? WHERE rowid = ?`).run(second._rowid, first._rowid)))
        .toMatch(ROWID_FROZEN);
      expect(refusal(() => db.prepare(`${verb} anchor_wallets SET rowid = 999999 WHERE rowid = ?`).run(second._rowid)))
        .toMatch(ROWID_FROZEN);
      expect(snapshot('anchor_wallets')).toEqual(before);
    });

    it('enrolling an enrolled wallet returns the stored enrolment, whatever the arguments', async () => {
      const before = snapshot('anchor_wallets');
      const again = await anchors.enrolAnchorWallet({ address: addr(w1), chain: CHAIN, domain, nonceBase: 9 });
      expect(again).toMatchObject({ address: addr(w1), nonceBase: 5, retiredAt: null });
      expect(snapshot('anchor_wallets')).toEqual(before);
    });
  });

  describe('anchor_wallet_txs', () => {
    it.each(REPLACING)('%s cannot rewrite an accounted transaction at its nonce', (verb) => {
      const before = snapshot('anchor_wallet_txs');
      expect(refusal(insert(verbInsert(verb), 'anchor_wallet_txs', txRow(5, 'rewritten')))).toMatch(GUARDED);
      expect(snapshot('anchor_wallet_txs')).toEqual(before);
    });

    it.each(EVERY_CLAUSE)('%s over an accounted transaction is refused by the guard', (_clause, sql) => {
      const before = snapshot('anchor_wallet_txs');
      const row = one('SELECT * FROM anchor_wallet_txs WHERE nonce = 5');
      expect(refusal(insert(sql, 'anchor_wallet_txs', { ...row, kind: 'handover' }))).toMatch(GUARDED);
      expect(snapshot('anchor_wallet_txs')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot delete a transaction by repeating its tx_hash at another nonce', (verb) => {
      const before = snapshot('anchor_wallet_txs');
      const held = one('SELECT tx_hash FROM anchor_wallet_txs WHERE nonce = 5').tx_hash;
      expect(refusal(insert(verbInsert(verb), 'anchor_wallet_txs', { ...txRow(6, 'other'), tx_hash: held }))).toMatch(GUARDED);
      expect(snapshot('anchor_wallet_txs')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot delete a transaction by naming its rowid', (verb) => {
      const before = snapshot('anchor_wallet_txs');
      const victim = one('SELECT rowid AS _rowid FROM anchor_wallet_txs WHERE nonce = 5');
      expect(refusal(insert(verbInsert(verb), 'anchor_wallet_txs', txRow(7, 'fresh', victim._rowid as number)))).toMatch(GUARDED);
      expect(snapshot('anchor_wallet_txs')).toEqual(before);
    });
  });

  describe('credential_events', () => {
    it.each(REPLACING)('%s cannot swap a registration’s public key', async (verb) => {
      const before = snapshot('credential_events');
      const registration = one(`SELECT * FROM credential_events WHERE credential_id = 'cred-1' AND event_type = 'registered'`);
      const { seq: _seq, ...row } = registration;
      expect(refusal(insert(verbInsert(verb), 'credential_events', { ...row, public_key: MALLORYKEY }))).toMatch(GUARDED);
      expect(snapshot('credential_events')).toEqual(before);
      expect((await credentials.getByCredentialId('cred-1'))!.publicKey).toBe(GOODKEY);
    });

    it.each(REPLACING)('%s cannot rewrite a revocation', async (verb) => {
      const before = snapshot('credential_events');
      const revocation = one(`SELECT * FROM credential_events WHERE credential_id = 'cred-2' AND event_type = 'revoked'`);
      const { seq: _seq, ...row } = revocation;
      expect(refusal(insert(verbInsert(verb), 'credential_events', { ...row, occurred_at: '2027-01-01T00:00:00.000Z', reason: 'rotated' })))
        .toMatch(GUARDED);
      expect(snapshot('credential_events')).toEqual(before);
      expect((await credentials.getByCredentialId('cred-2'))!.revocationReason).toBe('lost');
    });

    it.each(EVERY_CLAUSE)('%s over an existing event is refused by the guard', (_clause, sql) => {
      const before = snapshot('credential_events');
      expect(refusal(insert(sql, 'credential_events', one('SELECT * FROM credential_events ORDER BY seq LIMIT 1')))).toMatch(GUARDED);
      expect(snapshot('credential_events')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot delete a registration by naming its seq', async (verb) => {
      const before = snapshot('credential_events');
      const registration = one(`SELECT seq FROM credential_events WHERE credential_id = 'cred-1' AND event_type = 'registered'`);
      expect(refusal(insert(verbInsert(verb), 'credential_events', eventRow({ seq: registration.seq, credential_id: 'cred-3' }))))
        .toMatch(GUARDED);
      expect(snapshot('credential_events')).toEqual(before);
      expect((await credentials.getByCredentialId('cred-1'))!.publicKey).toBe(GOODKEY);
    });

    it('a registration planted at seq 0, ahead of the real one, is refused: the first registration is the one that counts', async () => {
      const before = snapshot('credential_events');
      expect(refusal(insert(verbInsert('INSERT INTO'), 'credential_events', eventRow({ seq: 0 })))).toMatch(BACKDATED);
      expect(snapshot('credential_events')).toEqual(before);
      expect((await credentials.getByCredentialId('cred-1'))!.publicKey).toBe(GOODKEY);
    });

    it('a revocation planted ahead of the real one is refused', async () => {
      const before = snapshot('credential_events');
      const firstSeq = one('SELECT MIN(seq) AS s FROM credential_events').s as number;
      const planted = eventRow({ seq: firstSeq + 1, event_id: 'e-early', credential_id: 'cred-2', event_type: 'revoked', public_key: null, reason: 'forged' });
      // firstSeq + 1 is cred-2's registration: a taken seq is the duplicate it is.
      expect(refusal(insert(verbInsert('INSERT INTO'), 'credential_events', planted))).toMatch(GUARDED);
      expect(refusal(insert(verbInsert('INSERT INTO'), 'credential_events', { ...planted, seq: 0 }))).toMatch(BACKDATED);
      expect(snapshot('credential_events')).toEqual(before);
      expect((await credentials.getByCredentialId('cred-2'))!.revocationReason).toBe('lost');
    });

    it('an explicit seq above the last is accepted, and folds last', async () => {
      const last = one('SELECT MAX(seq) AS s FROM credential_events').s as number;
      insert(verbInsert('INSERT INTO'), 'credential_events', eventRow({ seq: last + 10 }))();
      // A second registration of cred-1 changes nothing: the first one counts.
      expect((await credentials.getByCredentialId('cred-1'))!.publicKey).toBe(GOODKEY);
    });
  });

  // These tables refuse every UPDATE, so a rowid cannot be moved on them either.
  it.each(['store_identity', 'logs', 'log_leaves', 'anchor_wallet_txs', 'credential_events'])(
    'UPDATE OR REPLACE cannot move a %s row to another rowid',
    (table) => {
      const before = snapshot(table);
      const [first, second] = before;
      const target = second ? second._rowid : 999999;
      expect(refusal(() => db.prepare(`UPDATE OR REPLACE ${table} SET rowid = ? WHERE rowid = ?`).run(target, first._rowid)))
        .toMatch(UPDATE_REFUSED);
      expect(snapshot(table)).toEqual(before);
    },
  );

  describe('a rowid is never negative', () => {
    // Each *_block_replace guard reads NEW.rowid as -1 when an insert names
    // no rowid. A row planted at -1 would make every later insert on its table
    // collide with it. (store_identity's CHECK allows only singleton 1.)
    const plant: Record<string, () => Promise<unknown>> = {
      logs: async () => insert(verbInsert('INSERT INTO'), 'logs', await freshLogRow('chain-ghost', -1))(),
      // A leaf of the anchor log, at its next index: a row every guard but
      // the rowid's accepts (an evidence leaf must copy a stored record).
      log_leaves: async () => insert(verbInsert('INSERT INTO'), 'log_leaves', {
        rowid: -1, log_id: anchorLog.logId, leaf_index: (await logs.getLogSize(anchorLog.logId)).size, leaf_digest: hex('ghost'), source_ref: 'ghost',
        source: 'scheduler', logged_at: NOW,
      })(),
      log_checkpoints: async () => insert(verbInsert('INSERT INTO'), 'log_checkpoints', { rowid: -1, ...checkpointRow(checkpointFor(anchorLog, 3)) })(),
      anchor_publications: async () => insert(verbInsert('INSERT INTO'), 'anchor_publications', freshPublicationRow('rfc3161/1', 1, -1))(),
      anchor_wallets: async () => insert(verbInsert('INSERT INTO'), 'anchor_wallets', {
        rowid: -1, address: addr(w3), chain: CHAIN, domain, nonce_base: 0, enrolled_at: '2026-09-27T12:00:00.000Z',
      })(),
      anchor_wallet_txs: async () => insert(verbInsert('INSERT INTO'), 'anchor_wallet_txs', txRow(8, 'ghost', -1))(),
      credential_events: async () => insert(verbInsert('INSERT INTO'), 'credential_events', eventRow({ seq: -1, credential_id: 'cred-ghost' }))(),
    };
    /** The SDK's next write to each table, which a plant at -1 would have refused. */
    const nextWrite: Record<string, () => Promise<unknown>> = {
      logs: () => adapter.store(makeEnvelope({ evidenceId: 'ev-z1', sequenceNumber: 1 }), 'chain-z'),
      log_leaves: () => adapter.store(makeEnvelope({ evidenceId: 'ev-4', sequenceNumber: 4 })),
      log_checkpoints: () => anchors.insertLogCheckpoint(checkpointFor(anchorLog, 3)),
      anchor_publications: async () => anchors.insertAnchorPublication({
        epochId: 3, anchorSize: 2, p: (await anchors.getLogCheckpoint(anchorLog.logId, 2))!.bodyDigest, kind: 'rfc3161/1',
      }),
      anchor_wallets: () => anchors.enrolAnchorWallet({ address: addr(w3), chain: CHAIN, domain, nonceBase: 0 }),
      anchor_wallet_txs: async () => anchors.insertAnchorWalletTx({ address: addr(w1), chain: CHAIN, nonce: 6, kind: 'handover', ...(await signedTx(w1, 6)) }),
      credential_events: () => credentials.register(credential('cred-3', GOODKEY)),
    };

    it.each(Object.keys(plant))('%s refuses a row at rowid -1, and the SDK’s next write goes through', async (table) => {
      const before = snapshot(table);
      let message = '';
      try {
        await plant[table]();
      } catch (err) {
        message = (err as Error).message;
      }
      expect(message).toMatch(NEGATIVE_ROWID);
      expect(snapshot(table)).toEqual(before);
      await nextWrite[table]();
      expect(snapshot(table).length).toBeGreaterThan(before.length);
    });
  });

  describe('the SDK’s own writes go through', () => {
    it('records and their leaves, per-store logs, leaves, checkpoints and signatures, publications, wallets, credentials', async () => {
      // beforeEach stored three records, grew the anchor log, stored two
      // checkpoints, took a publication to finalized, took the lease,
      // enrolled two wallets, accounted a transaction, and registered two
      // credentials and revoked one.
      expect(await logs.getLogSize(evidenceLog.logId)).toEqual({ size: 3, leafCount: 3 });
      expect((await anchors.ensureStoreLog('anchors')).logId).toBe(anchorLog.logId);
      const custody = await anchors.ensureStoreLog('custody');
      expect((await anchors.ensureStoreLog('custody')).logId).toBe(custody.logId);

      await adapter.store(makeEnvelope({ evidenceId: 'ev-4', sequenceNumber: 4 }));
      await adapter.store(makeEnvelope({ evidenceId: 'ev-z1', sequenceNumber: 1 }), 'chain-z');
      expect(await logs.getLogSize(evidenceLog.logId)).toEqual({ size: 4, leafCount: 4 });
      expect(await logs.getEvidenceLog('chain-z')).not.toBeNull();

      await anchors.appendLogLeaves(custody.logId, [{ leafIndex: 0, leafDigest: hex('c0'), sourceRef: 'c0' }]);
      await anchors.insertLogCheckpoint(checkpointFor(custody, 1));
      await anchors.appendCheckpointSignatures(custody.logId, 1, ['sig-a']);
      await anchors.appendCheckpointSignatures(custody.logId, 1, ['sig-b']);
      expect((await anchors.getLogCheckpoint(custody.logId, 1))!.signatures).toEqual(['sig-a', 'sig-b']);

      const obtained = await anchors.updateAnchorPublication(
        (await anchors.insertAnchorPublication({
          epochId: 2, anchorSize: 2, p: (await anchors.getLogCheckpoint(anchorLog.logId, 2))!.bodyDigest, kind: 'rfc3161/1',
        })).id,
        { state: 'obtained', token: Buffer.from('token').toString('base64'), genTime: '2026-09-27T10:00:00Z' },
      );
      expect(obtained.state).toBe('obtained');
      await anchors.updateAnchorPublication(prepared.id, {
        state: 'submitted', fromAddress: SENDER, nonce: 2, attempts: [attempt(2)],
      });

      expect((await anchors.enrolAnchorWallet({ address: addr(w3), chain: CHAIN, domain, nonceBase: 1 })).nonceBase).toBe(1);
      expect((await anchors.enrolAnchorWallet({ address: addr(w3), chain: CHAIN, domain, nonceBase: 4 })).nonceBase).toBe(1);
      expect((await anchors.retireAnchorWallet(addr(w3), CHAIN)).retiredAt).not.toBeNull();
      await anchors.insertAnchorWalletTx({ address: addr(w1), chain: CHAIN, nonce: 6, kind: 'handover', ...(await signedTx(w1, 6)) });
      expect((await anchors.listAnchorWalletTxs(addr(w1), CHAIN)).map((t) => t.nonce)).toEqual([5, 6]);

      await credentials.register(credential('cred-3', GOODKEY));
      await credentials.updateCounter('cred-3', 4);
      await credentials.updateCounter('cred-3', 2);
      await credentials.revoke('cred-3', { reason: 'rotated' });
      expect((await credentials.history('cred-3')).map((e) => e.type)).toEqual(['registered', 'counter_regressed', 'revoked']);
    });
  });

  it('a store written before the guards existed gets them when it is opened', async () => {
    const guards = [
      'store_identity_block_replace',
      'logs_block_replace',
      'logs_block_negative_rowid',
      'logs_block_backdated_id',
      'log_leaves_block_replace',
      'log_leaves_block_negative_rowid',
      'log_checkpoints_block_replace',
      'log_checkpoints_block_negative_rowid',
      'log_checkpoints_block_rowid_change',
      'anchor_publications_block_replace',
      'anchor_publications_block_negative_rowid',
      'anchor_publications_block_nonce_replace',
      'anchor_publications_block_backdated_id',
      'anchor_lease_block_rowid_change',
      'anchor_wallets_block_replace',
      'anchor_wallets_block_negative_rowid',
      'anchor_wallets_block_rowid_change',
      'anchor_wallet_txs_block_replace',
      'anchor_wallet_txs_block_negative_rowid',
      'credential_events_block_replace',
      'credential_events_block_negative_rowid',
      'credential_events_block_backdated_seq',
    ].sort();
    await adapter.close();
    const raw = new Database(dbPath);
    try {
      for (const name of guards) raw.exec(`DROP TRIGGER IF EXISTS ${name}`);
      expect(raw.prepare(`SELECT name FROM sqlite_master WHERE type = 'trigger' AND name IN (${placeholders(guards)})`).all(...guards))
        .toEqual([]);
    } finally {
      raw.close();
    }

    await open();
    const installed = all(
      `SELECT name FROM sqlite_master WHERE type = 'trigger' AND name IN (${placeholders(guards)}) ORDER BY name`,
      ...guards,
    ).map((r) => r.name);
    expect(installed).toEqual(guards);
    const row = { ...one('SELECT * FROM store_identity'), store_id: 'f'.repeat(32) };
    expect(refusal(insert(verbInsert('INSERT OR REPLACE INTO'), 'store_identity', row))).toMatch(GUARDED);
    expect(refusal(() => db.prepare('UPDATE log_checkpoints SET rowid = 999999 WHERE tree_size = 1').run())).toMatch(ROWID_FROZEN);
    expect(refusal(insert(verbInsert('INSERT INTO'), 'credential_events', eventRow({ seq: 0 })))).toMatch(BACKDATED);
  });
});
