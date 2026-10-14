/**
 * On SQLite, neither an insert nor a rowid change replaces a row of an
 * append-only table.
 *
 * SQLite's REPLACE conflict resolution deletes the row an insert or an update
 * conflicts with. That delete fires a DELETE trigger only under
 * `recursive_triggers`, and no UPDATE trigger fires at all, so the triggers
 * that refuse UPDATE and DELETE do not, on their own, stop a writer holding
 * the file from swapping a row, with `INSERT OR REPLACE` over its key or with
 * `UPDATE OR REPLACE ... SET rowid = <its rowid>` followed by a plain insert.
 * On the seven tables of sqlite.ts that keep append-only records
 * (`envelopes`, `chains`, `envelope_revisions`, `custody_entries`,
 * `chain_annotations`, `chain_relinks`, `chain_forks`):
 *
 *   - `<table>_block_replace`, BEFORE INSERT and so before conflict handling,
 *     refuses an insert naming a key a row already holds: its primary key,
 *     its rowid, and for `custody_entries` its `entry_hash`. The conflict
 *     clause makes no difference.
 *   - `<table>_block_negative_rowid`, AFTER INSERT, refuses a row at a
 *     negative rowid: the guard above reads NEW.rowid as -1 for an insert that
 *     names none, so a row planted at -1 would collide with every later one.
 *   - `envelopes_block_rowid_change` and `chains_block_rowid_change` refuse
 *     any change to a rowid; the other five tables refuse every UPDATE.
 *   - `custody_entries_block_backdated_id` refuses a custody row at an
 *     explicit id below the ledger's last one, where it would read first.
 *
 * Every attack is a raw statement on the adapter's own connection, the way an
 * insider with the file open would issue it.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createHash } from 'crypto';
import Database from 'better-sqlite3';
import {
  canonicalCustodyMetadata,
  computeCustodyEntryHash,
} from '@tzun/engine';
import type { EvidenceEnvelope } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { DuplicateRecordError } from '../../src/storage/append-only';
import { makeAnnotation, makeEnvelope, makeFork, makeRelink } from './storage-conformance/fixtures';

type Db = import('better-sqlite3').Database;

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

const GUARDED = /INSERT over an existing row refused/;
const ROWID_FROZEN = /rowid is immutable/;
const NEGATIVE_ROWID = /rowid cannot be negative/;
const BACKDATED_ID = /explicit id must be above every existing id/;
const AHEAD_OF_FIRST = /explicit rowid cannot be below the first row/;

/** Every table with a `*_block_replace` guard. */
const APPEND_ONLY_TABLES = [
  'chain_annotations',
  'chain_forks',
  'chain_relinks',
  'chains',
  'custody_entries',
  'envelope_revisions',
  'envelopes',
] as const;

/** Every guard this file is about, as sqlite_master names them. */
const GUARDS = [
  ...APPEND_ONLY_TABLES.map((t) => `${t}_block_replace`),
  ...APPEND_ONLY_TABLES.map((t) => `${t}_block_negative_rowid`),
  'chains_block_rowid_change',
  'custody_entries_block_backdated_id',
  'envelopes_block_low_rowid',
  'envelopes_block_rowid_change',
].sort();

/**
 * The ways an UPDATE can move a row to another rowid. UPDATE OR REPLACE to a
 * rowid another row holds deletes that row, as INSERT OR REPLACE does, and
 * fires no DELETE trigger; the others would move the row or be skipped.
 */
const ROWID_UPDATES = ['UPDATE', 'UPDATE OR REPLACE', 'UPDATE OR IGNORE', 'UPDATE OR FAIL'] as const;

/**
 * The ways an INSERT can meet an existing key. The first three would replace
 * the row; the rest would fail on the key or be skipped, or, for the upsert,
 * rewrite the row in place. The guard refuses every one of them before
 * conflict handling, so no conflict clause is a way past it.
 */
const REPLACING = ['INSERT OR REPLACE INTO', 'REPLACE INTO'] as const;
const EVERY_CLAUSE: Array<[string, (table: string, columns: string[]) => string]> = [
  ['INSERT OR REPLACE', (t, c) => `INSERT OR REPLACE INTO ${t} (${c.join(', ')}) VALUES (${c.map(() => '?').join(', ')})`],
  ['REPLACE INTO', (t, c) => `REPLACE INTO ${t} (${c.join(', ')}) VALUES (${c.map(() => '?').join(', ')})`],
  ['INSERT OR REPLACE ... SELECT', (t, c) => `INSERT OR REPLACE INTO ${t} (${c.join(', ')}) SELECT ${c.map(() => '?').join(', ')}`],
  ['INSERT OR IGNORE', (t, c) => `INSERT OR IGNORE INTO ${t} (${c.join(', ')}) VALUES (${c.map(() => '?').join(', ')})`],
  ['INSERT OR FAIL', (t, c) => `INSERT OR FAIL INTO ${t} (${c.join(', ')}) VALUES (${c.map(() => '?').join(', ')})`],
  ['INSERT OR ABORT', (t, c) => `INSERT OR ABORT INTO ${t} (${c.join(', ')}) VALUES (${c.map(() => '?').join(', ')})`],
  ['plain INSERT', (t, c) => `INSERT INTO ${t} (${c.join(', ')}) VALUES (${c.map(() => '?').join(', ')})`],
  ['ON CONFLICT DO NOTHING', (t, c) => `INSERT INTO ${t} (${c.join(', ')}) VALUES (${c.map(() => '?').join(', ')}) ON CONFLICT DO NOTHING`],
  ['ON CONFLICT DO UPDATE', (t, c) =>
    `INSERT INTO ${t} (${c.join(', ')}) VALUES (${c.map(() => '?').join(', ')}) ON CONFLICT DO UPDATE SET ${c.map((x) => `${x} = excluded.${x}`).join(', ')}`],
];

const ENVELOPE_COLUMNS = ['evidence_id', 'envelope', 'captured_at', 'captured_at_ms', 'ai_system_id', 'digest', 'chain_id'];
const CHAIN_COLUMNS = ['chain_id', 'parent_chain_id', 'fork_point', 'status', 'created_at', 'sealed_at'];
const REVISION_COLUMNS = ['evidence_id', 'revision_no', 'canonical_digest', 'chain_link', 'recorded_at', 'cause', 'actor'];
const CUSTODY_COLUMNS = [
  'evidence_id', 'chain_id', 'canonical_digest', 'action', 'actor', 'ts', 'system_id',
  'metadata', 'metadata_canonical', 'prev_entry_hash', 'entry_hash', 'recovery_id',
];
const ANNOTATION_COLUMNS = ['id', 'incident_id', 'affected_records', 'annotated_at', 'annotated_by', 'notes', 'original_digests'];
const RELINK_COLUMNS = ['id', 'incident_id', 'relinked_at', 'relinked_by', 'from_sequence', 'to_sequence', 'modified_links'];
const FORK_COLUMNS = [
  'id', 'incident_id', 'forked_at', 'forked_by', 'reason', 'old_chain_id', 'new_chain_id',
  'fork_after_sequence', 'sealed_old_chain_length', 'sealed_old_chain_head',
];

/**
 * The recovery records, whose UPDATE and DELETE triggers refuse every row
 * edit: for each, the row beforeEach writes and the rewrite an insider would
 * want.
 */
const RECOVERY_TABLES = [
  {
    table: 'chain_relinks', id: 'rlk-1', columns: RELINK_COLUMNS,
    rewrite: { relinked_by: 'mallory', modified_links: '[]' },
  },
  {
    table: 'chain_forks', id: 'f1', columns: FORK_COLUMNS,
    // Lowering the sealed chain's high-water mark to match a deleted tail
    // would make the deletion invisible.
    rewrite: { sealed_old_chain_head: 3 },
  },
  {
    table: 'chain_annotations', id: 'ann-1', columns: ANNOTATION_COLUMNS,
    rewrite: { annotated_by: 'mallory', original_digests: '{}' },
  },
] as const;

describe('SQLite: an insert never replaces a row of an append-only table', () => {
  let dir: string;
  let dbPath: string;
  let adapter: SqliteStorageAdapter;
  let db: Db;

  const RELINKED_LINK = hex('relinked-link');

  beforeEach(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-'));
    dbPath = path.join(dir, 'evidence.db');
    adapter = new SqliteStorageAdapter(dbPath);
    db = (adapter as unknown as { db: Db }).db;
    await adapter.store(makeEnvelope({ evidenceId: 'ev-1', sequenceNumber: 1 }));
    await adapter.store(makeEnvelope({ evidenceId: 'ev-2', sequenceNumber: 2 }));
    // A relink of ev-2: its link rewritten, revision 1 recorded, the relink
    // record stored and a hashed `relinked` custody entry ledgered and
    // mirrored into the record's copy, all in one transaction.
    await adapter.applyRelink(
      makeRelink({
        id: 'rlk-1',
        modifiedLinks: [{ evidenceId: 'ev-2', sequenceNumber: 2, previousChainLink: null, newChainLink: RELINKED_LINK }],
      }),
      [{
        evidenceId: 'ev-2',
        entry: { timestamp: '2026-09-26T10:00:00.000Z', actor: 'alice@acme.example', action: 'relinked', systemId: 'tzun-recovery' },
      }],
    );
    await adapter.storeChain({ chainId: 'chain-s', status: 'active', createdAt: '2026-09-26T09:00:00.000Z' });
    await adapter.sealChain('chain-s', '2026-09-26T09:30:00.000Z');
    await adapter.storeChain({ chainId: 'chain-a', status: 'active', createdAt: '2026-09-26T09:45:00.000Z' });
    await adapter.storeAnnotation(makeAnnotation({ id: 'ann-1', affectedRecords: ['ev-1'], originalDigests: { 'ev-1': hex('ev-1') } }));
    await adapter.storeFork({
      ...makeFork({ id: 'f1', oldChainId: 'chain-s', newChainId: 'chain-a', forkAfterSequence: 5, sealedOldChainLength: 5 }),
      sealedOldChainHead: 5,
    });
  });

  afterEach(async () => {
    await adapter.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const all = (sql: string, ...params: unknown[]) => db.prepare(sql).all(...params) as Array<Record<string, unknown>>;
  const one = (sql: string, ...params: unknown[]) => db.prepare(sql).get(...params) as Record<string, unknown>;
  /** Every row of `table` with its rowid, in rowid order: what a refused statement must leave exactly as it was. */
  const snapshot = (table: string) => all(`SELECT rowid AS _rowid, * FROM ${table} ORDER BY rowid`);
  const placeholders = (columns: readonly string[]) => columns.map(() => '?').join(', ');

  /** The custody row the adapter would write next for ev-2: it extends the ledger's tail and recomputes. */
  function nextCustodyRow(): Record<string, unknown> {
    const envelope = JSON.parse(one('SELECT envelope FROM envelopes WHERE evidence_id = ?', 'ev-2').envelope as string) as EvidenceEnvelope;
    const tail = one('SELECT entry_hash FROM custody_entries WHERE evidence_id = ? ORDER BY id DESC LIMIT 1', 'ev-2');
    const fields = {
      evidenceId: 'ev-2',
      canonicalDigest: envelope.integrity.canonicalDigest,
      action: 'reviewed',
      actor: 'mallory@acme.example',
      timestamp: '2026-09-26T11:00:00.000Z',
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

  /** Insert `row` into custody_entries at the explicit `id`. */
  const insertCustodyAt = (id: number, row: Record<string, unknown>) => () =>
    db.prepare(`INSERT INTO custody_entries (id, ${CUSTODY_COLUMNS.join(', ')}) VALUES (?, ${placeholders(CUSTODY_COLUMNS)})`)
      .run(id, ...CUSTODY_COLUMNS.map((c) => row[c]));

  describe('envelopes', () => {
    const envelopeRow = (id: string) => one('SELECT rowid AS _rowid, * FROM envelopes WHERE evidence_id = ?', id);
    const stored = (id: string): EvidenceEnvelope => JSON.parse(envelopeRow(id).envelope as string);
    const values = (row: Record<string, unknown>, envelope: unknown): unknown[] =>
      [row.evidence_id, JSON.stringify(envelope), row.captured_at, row.captured_at_ms, row.ai_system_id, row.digest, row.chain_id];
    /** `verb` the row of `id` back in, with its envelope rewritten by `mutate`. */
    const replaceWith = (verb: string, id: string, mutate: (e: EvidenceEnvelope) => void, digest?: string) => () => {
      const row = envelopeRow(id);
      const envelope = stored(id);
      mutate(envelope);
      const params = values(row, envelope);
      if (digest !== undefined) params[5] = digest;
      db.prepare(`${verb} envelopes (${ENVELOPE_COLUMNS.join(', ')}) VALUES (${ENVELOPE_COLUMNS.map(() => '?').join(', ')})`)
        .run(...params);
    };

    it.each(REPLACING)('%s cannot drop a relinked custody entry from the record’s copy', (verb) => {
      const before = snapshot('envelopes');
      expect(stored('ev-2').custodyChain.map((e) => e.action)).toEqual(['decision_captured', 'relinked']);
      expect(refusal(replaceWith(verb, 'ev-2', (e) => { e.custodyChain.pop(); }))).toMatch(GUARDED);
      expect(snapshot('envelopes')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot add a forged mirror entry', (verb) => {
      const before = snapshot('envelopes');
      expect(refusal(replaceWith(verb, 'ev-1', (e) => {
        e.custodyChain.push({
          timestamp: '2026-09-26T11:00:00.000Z', actor: 'mallory@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
          entryHash: hex('forged-entry'), prevEntryHash: null,
        });
      }))).toMatch(GUARDED);
      expect(snapshot('envelopes')).toEqual(before);
    });

    it.each(REPLACING)('%s cannot rewrite the payload and the digest', (verb) => {
      const before = snapshot('envelopes');
      const rewritten = hex('rewritten-ev-1');
      expect(refusal(replaceWith(verb, 'ev-1', (e) => {
        e.payload.reason = 'rewritten';
        e.integrity.canonicalDigest = rewritten;
      }, rewritten))).toMatch(GUARDED);
      expect(snapshot('envelopes')).toEqual(before);
    });

    it('INSERT OR REPLACE cannot displace another record by naming its rowid', () => {
      const before = snapshot('envelopes');
      const victim = envelopeRow('ev-1');
      const intruder = makeEnvelope({ evidenceId: 'ev-intruder', sequenceNumber: 3 });
      expect(refusal(() => db.prepare(
        `INSERT OR REPLACE INTO envelopes (rowid, ${ENVELOPE_COLUMNS.join(', ')}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(victim._rowid, 'ev-intruder', JSON.stringify(intruder), intruder.payload.capturedAt, 0,
        intruder.payload.aiSystemId, intruder.integrity.canonicalDigest, 'default'))).toMatch(GUARDED);
      expect(snapshot('envelopes')).toEqual(before);
    });

    it.each(EVERY_CLAUSE)('%s over an existing evidence_id is refused by the guard', (_clause, sql) => {
      const before = snapshot('envelopes');
      const row = envelopeRow('ev-1');
      expect(refusal(() => db.prepare(sql('envelopes', ENVELOPE_COLUMNS)).run(...values(row, stored('ev-1')))))
        .toMatch(GUARDED);
      expect(snapshot('envelopes')).toEqual(before);
    });

    // Tzun.init() judges a store by its first record, the lowest rowid (the
    // 0.7.0 store check), so a row planted ahead of it would decide whether
    // the store opens.
    describe('no record is written ahead of the first', () => {
      const insertAt = (rowid: number, id: string) => () => {
        const intruder = makeEnvelope({ evidenceId: id, sequenceNumber: 1 });
        db.prepare(`INSERT INTO envelopes (rowid, ${ENVELOPE_COLUMNS.join(', ')}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(rowid, id, JSON.stringify(intruder), intruder.payload.capturedAt, 0, intruder.payload.aiSystemId,
            intruder.integrity.canonicalDigest, `chain-of-${id}`);
      };
      const firstByRowid = () => one('SELECT evidence_id FROM envelopes ORDER BY rowid ASC LIMIT 1').evidence_id;

      it('a plain insert at an explicit rowid below the first row’s is refused, and the first record stays first', () => {
        const before = snapshot('envelopes');
        const first = envelopeRow('ev-1')._rowid as number;
        expect(first).toBe(1);
        expect(refusal(insertAt(0, 'ev-planted'))).toMatch(AHEAD_OF_FIRST);
        expect(snapshot('envelopes')).toEqual(before);
        expect(firstByRowid()).toBe('ev-1');
      });

      // A record planted at rowid 0 is refused whatever the conflict clause,
      // so it cannot become the first record the store check reads.
      it.each(EVERY_CLAUSE)('%s at rowid 0 is refused, and the first record stays first', (_clause, sql) => {
        const before = snapshot('envelopes');
        const intruder = makeEnvelope({ evidenceId: 'ev-planted', sequenceNumber: 1 });
        expect(refusal(() => db.prepare(sql('envelopes', ['rowid', ...ENVELOPE_COLUMNS])).run(
          0, 'ev-planted', JSON.stringify(intruder), intruder.payload.capturedAt, 0, intruder.payload.aiSystemId,
          intruder.integrity.canonicalDigest, 'default',
        ))).toMatch(AHEAD_OF_FIRST);
        expect(snapshot('envelopes')).toEqual(before);
        expect(firstByRowid()).toBe('ev-1');
      });

      it('an explicit rowid above the first row’s is accepted: it puts nothing first', () => {
        insertAt(1000, 'ev-later')();
        expect(firstByRowid()).toBe('ev-1');
      });

      it('an empty table takes a first row at any rowid that is not negative', () => {
        const empty = new Database(path.join(dir, 'empty.db'));
        try {
          empty.exec('CREATE TABLE envelopes (evidence_id TEXT PRIMARY KEY)');
          const trigger = one(`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'envelopes_block_low_rowid'`).sql as string;
          empty.exec(trigger);
          empty.prepare('INSERT INTO envelopes (rowid, evidence_id) VALUES (0, ?)').run('ev-0');
          expect(refusal(() => empty.prepare('INSERT INTO envelopes (rowid, evidence_id) VALUES (-5, ?)').run('ev-neg'))).toMatch(AHEAD_OF_FIRST);
          empty.prepare('INSERT INTO envelopes (evidence_id) VALUES (?)').run('ev-next');
        } finally {
          empty.close();
        }
      });
    });

    describe('a record’s rowid never changes', () => {
      const rowidOf = (id: string) => envelopeRow(id)._rowid as number;

      it.each(ROWID_UPDATES)('%s cannot move a record onto another record’s rowid', (verb) => {
        // UPDATE OR REPLACE would delete ev-1 here, and fire no DELETE trigger.
        const before = snapshot('envelopes');
        expect(refusal(() => db.prepare(`${verb} envelopes SET rowid = ? WHERE evidence_id = ?`).run(rowidOf('ev-1'), 'ev-2')))
          .toMatch(ROWID_FROZEN);
        expect(snapshot('envelopes')).toEqual(before);
      });

      it.each(ROWID_UPDATES)('%s cannot move a record to a free rowid, which would change head()', async (verb) => {
        const before = snapshot('envelopes');
        expect((await adapter.head())!.payload.evidenceId).toBe('ev-2');
        expect(refusal(() => db.prepare(`${verb} envelopes SET rowid = 999999 WHERE evidence_id = ?`).run('ev-1')))
          .toMatch(ROWID_FROZEN);
        expect(snapshot('envelopes')).toEqual(before);
        expect((await adapter.head())!.payload.evidenceId).toBe('ev-2');
      });

      /**
       * The two-statement rewrite: move another record onto the victim's
       * rowid with UPDATE OR REPLACE, which deletes the victim, then insert
       * the victim again rewritten. Each step is refused on its own.
       */
      it.each([
        ['drop the relinked custody entry from ev-2', 'ev-2', 'ev-1', (e: EvidenceEnvelope) => { e.custodyChain.pop(); }, undefined],
        ['add a forged mirror entry to ev-2', 'ev-2', 'ev-1', (e: EvidenceEnvelope) => {
          e.custodyChain.push({
            timestamp: '2026-09-26T11:00:00.000Z', actor: 'mallory@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
            entryHash: hex('forged-entry'), prevEntryHash: e.custodyChain[e.custodyChain.length - 1]!.entryHash ?? null,
          });
        }, undefined],
        ['rewrite ev-1’s payload and digest', 'ev-1', 'ev-2', (e: EvidenceEnvelope) => {
          e.payload.reason = 'rewritten';
          e.integrity.canonicalDigest = hex('rewritten-ev-1');
        }, hex('rewritten-ev-1')],
      ] as const)('the two-statement rewrite cannot %s', async (_what, victim, mover, mutate, digest) => {
        const before = snapshot('envelopes');
        const original = await adapter.retrieve(victim);

        expect(refusal(() => db.prepare('UPDATE OR REPLACE envelopes SET rowid = ? WHERE evidence_id = ?')
          .run(rowidOf(victim), mover))).toMatch(ROWID_FROZEN);
        expect(refusal(replaceWith('INSERT INTO', victim, mutate, digest))).toMatch(GUARDED);

        expect(snapshot('envelopes')).toEqual(before);
        expect(await adapter.retrieve(victim)).toEqual(original);
      });
    });
  });

  describe('chains', () => {
    const chainValues = (overrides: Record<string, unknown> = {}): unknown[] => {
      const row = { ...one('SELECT * FROM chains WHERE chain_id = ?', 'chain-s'), ...overrides };
      return CHAIN_COLUMNS.map((c) => row[c]);
    };

    it.each(REPLACING)('%s cannot lift a seal', (verb) => {
      const before = snapshot('chains');
      expect(refusal(() => db.prepare(
        `${verb} chains (${CHAIN_COLUMNS.join(', ')}) VALUES (${CHAIN_COLUMNS.map(() => '?').join(', ')})`,
      ).run(...chainValues({ status: 'active', sealed_at: null })))).toMatch(GUARDED);
      expect(snapshot('chains')).toEqual(before);
      expect(one('SELECT status FROM chains WHERE chain_id = ?', 'chain-s').status).toBe('sealed');
    });

    it('INSERT OR REPLACE cannot displace another chain by naming its rowid', () => {
      const before = snapshot('chains');
      const victim = one('SELECT rowid AS _rowid FROM chains WHERE chain_id = ?', 'chain-s');
      expect(refusal(() => db.prepare(
        `INSERT OR REPLACE INTO chains (rowid, ${CHAIN_COLUMNS.join(', ')}) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(victim._rowid, 'chain-intruder', null, null, 'active', '2026-09-26T12:00:00.000Z', null))).toMatch(GUARDED);
      expect(snapshot('chains')).toEqual(before);
    });

    it.each(EVERY_CLAUSE)('%s over an existing chain_id is refused by the guard', (_clause, sql) => {
      const before = snapshot('chains');
      expect(refusal(() => db.prepare(sql('chains', CHAIN_COLUMNS)).run(...chainValues()))).toMatch(GUARDED);
      expect(snapshot('chains')).toEqual(before);
    });

    describe('a chain’s rowid never changes', () => {
      const rowidOf = (id: string) => one('SELECT rowid AS _rowid FROM chains WHERE chain_id = ?', id)._rowid as number;

      it.each(ROWID_UPDATES)('%s cannot move a chain onto the sealed chain’s rowid', async (verb) => {
        // UPDATE OR REPLACE would delete chain-s here, and fire no DELETE trigger.
        const before = snapshot('chains');
        expect(refusal(() => db.prepare(`${verb} chains SET rowid = ? WHERE chain_id = ?`).run(rowidOf('chain-s'), 'chain-a')))
          .toMatch(ROWID_FROZEN);
        expect(snapshot('chains')).toEqual(before);
        await expect(
          adapter.storeChain({ chainId: 'chain-s', status: 'active', createdAt: '2026-09-26T12:00:00.000Z' }),
        ).rejects.toBeInstanceOf(DuplicateRecordError);
      });

      it.each(ROWID_UPDATES)('%s cannot move a chain to a free rowid', (verb) => {
        const before = snapshot('chains');
        expect(refusal(() => db.prepare(`${verb} chains SET rowid = 999999 WHERE chain_id = ?`).run('chain-s')))
          .toMatch(ROWID_FROZEN);
        expect(snapshot('chains')).toEqual(before);
      });

      it('the two-statement seal lift (move a chain onto its rowid, then insert it again as active) is refused at both steps', async () => {
        const before = snapshot('chains');
        expect(refusal(() => db.prepare('UPDATE OR REPLACE chains SET rowid = ? WHERE chain_id = ?').run(rowidOf('chain-s'), 'chain-a')))
          .toMatch(ROWID_FROZEN);
        expect(refusal(() => db.prepare(`INSERT INTO chains (chain_id, status, created_at) VALUES (?, 'active', ?)`)
          .run('chain-s', '2026-09-26T12:00:00.000Z'))).toMatch(GUARDED);
        expect(snapshot('chains')).toEqual(before);
        expect((await adapter.getChain('chain-s'))!.status).toBe('sealed');
      });
    });

    it('storeChain() of an existing chain id still throws DuplicateRecordError', async () => {
      const attempt = adapter.storeChain({ chainId: 'chain-s', status: 'active', createdAt: '2026-09-26T12:00:00.000Z' });
      await expect(attempt).rejects.toBeInstanceOf(DuplicateRecordError);
      await expect(
        adapter.storeChain({ chainId: 'chain-s', status: 'active', createdAt: '2026-09-26T12:00:00.000Z' }),
      ).rejects.toMatchObject({ recordType: 'Chain', recordId: 'chain-s' });
      expect(one('SELECT status FROM chains WHERE chain_id = ?', 'chain-s').status).toBe('sealed');
    });
  });

  describe('envelope_revisions', () => {
    const revisionValues = (overrides: Record<string, unknown> = {}): unknown[] => {
      const row = {
        ...one('SELECT * FROM envelope_revisions WHERE evidence_id = ? AND revision_no = 0', 'ev-1'),
        ...overrides,
      };
      return REVISION_COLUMNS.map((c) => row[c]);
    };

    it.each(REPLACING)('%s cannot reseat a record’s capture revision', async (verb) => {
      const before = snapshot('envelope_revisions');
      expect(refusal(() => db.prepare(
        `${verb} envelope_revisions (${REVISION_COLUMNS.join(', ')}) VALUES (${REVISION_COLUMNS.map(() => '?').join(', ')})`,
      ).run(...revisionValues({ canonical_digest: hex('reseated') })))).toMatch(GUARDED);
      expect(snapshot('envelope_revisions')).toEqual(before);
      expect(await adapter.getCaptureDigests(['ev-1'])).toEqual({ 'ev-1': hex('ev-1') });
    });

    it('INSERT OR REPLACE cannot delete a capture revision by naming its rowid', async () => {
      const before = snapshot('envelope_revisions');
      const victim = one('SELECT rowid AS _rowid FROM envelope_revisions WHERE evidence_id = ? AND revision_no = 0', 'ev-1');
      expect(refusal(() => db.prepare(
        `INSERT OR REPLACE INTO envelope_revisions (rowid, ${REVISION_COLUMNS.join(', ')}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(victim._rowid, 'ev-unrelated', 0, hex('unrelated'), null, '2026-09-26T12:00:00.000Z', 'capture', 'mallory'))).toMatch(GUARDED);
      expect(snapshot('envelope_revisions')).toEqual(before);
      expect(await adapter.getCaptureDigests(['ev-1'])).toEqual({ 'ev-1': hex('ev-1') });
    });

    it.each(EVERY_CLAUSE)('%s over an existing (evidence_id, revision_no) is refused by the guard', (_clause, sql) => {
      const before = snapshot('envelope_revisions');
      expect(refusal(() => db.prepare(sql('envelope_revisions', REVISION_COLUMNS)).run(...revisionValues())))
        .toMatch(GUARDED);
      expect(snapshot('envelope_revisions')).toEqual(before);
    });
  });

  describe('custody_entries', () => {
    const nextRow = nextCustodyRow;

    it.each(REPLACING)('%s cannot displace a ledger row by its id, even with a row that extends the chain', (verb) => {
      const before = snapshot('custody_entries');
      const [relinked] = all('SELECT id FROM custody_entries WHERE evidence_id = ?', 'ev-2');
      const row = nextRow();
      expect(refusal(() => db.prepare(
        `${verb} custody_entries (id, ${CUSTODY_COLUMNS.join(', ')}) VALUES (?, ${CUSTODY_COLUMNS.map(() => '?').join(', ')})`,
      ).run(relinked.id, ...CUSTODY_COLUMNS.map((c) => row[c])))).toMatch(GUARDED);
      expect(snapshot('custody_entries')).toEqual(before);
    });

    it('an explicit id below the ledger’s last id is refused, even for a row that extends the chain', async () => {
      // listCustodyEntries() reads in id order: a row written below the tail
      // would read first, ahead of the entries it follows.
      const before = snapshot('custody_entries');
      expect(refusal(insertCustodyAt(0, nextRow()))).toMatch(BACKDATED_ID);
      expect(snapshot('custody_entries')).toEqual(before);
      expect((await adapter.listCustodyEntries('ev-2')).map((e) => e.action)).toEqual(['relinked']);
    });

    it('an explicit id above the ledger’s last id is accepted, and reads last', async () => {
      const [{ maxId }] = all('SELECT MAX(id) AS maxId FROM custody_entries');
      insertCustodyAt((maxId as number) + 10, nextRow())();
      expect((await adapter.listCustodyEntries('ev-2')).map((e) => e.action)).toEqual(['relinked', 'reviewed']);
    });

    it('INSERT OR REPLACE cannot move a ledger row by repeating its entry_hash', () => {
      // The id-order guard refuses the plant below; it is dropped here so
      // the entry_hash key is tested on its own. A row that extends the
      // chain, written at an explicit id below the tail, names no key a row
      // holds.
      db.exec('DROP TRIGGER custody_entries_block_backdated_id');
      const row = nextRow();
      insertCustodyAt(0, row)();
      const before = snapshot('custody_entries');
      // The same row again, naming no id: REPLACE would delete id 0 and write
      // the row at a new id on the conflict over entry_hash.
      expect(refusal(() => db.prepare(
        `INSERT OR REPLACE INTO custody_entries (${CUSTODY_COLUMNS.join(', ')}) VALUES (${CUSTODY_COLUMNS.map(() => '?').join(', ')})`,
      ).run(...CUSTODY_COLUMNS.map((c) => row[c])))).toMatch(GUARDED);
      expect(snapshot('custody_entries')).toEqual(before);
    });

    it.each(EVERY_CLAUSE)('%s over an existing id is refused by the guard', (_clause, sql) => {
      const before = snapshot('custody_entries');
      const [relinked] = all('SELECT id FROM custody_entries WHERE evidence_id = ?', 'ev-2');
      const row = nextRow();
      expect(refusal(() => db.prepare(sql('custody_entries', ['id', ...CUSTODY_COLUMNS]))
        .run(relinked.id, ...CUSTODY_COLUMNS.map((c) => row[c])))).toMatch(GUARDED);
      expect(snapshot('custody_entries')).toEqual(before);
    });
  });

  describe.each(RECOVERY_TABLES)('$table', ({ table, id, columns, rewrite }) => {
    const rowValues = (overrides: Record<string, unknown> = {}): unknown[] => {
      const row = { ...one(`SELECT * FROM ${table} WHERE id = ?`, id), ...overrides };
      return columns.map((c) => row[c]);
    };

    it.each(REPLACING)('%s cannot rewrite a row', (verb) => {
      const before = snapshot(table);
      expect(refusal(() => db.prepare(`${verb} ${table} (${columns.join(', ')}) VALUES (${placeholders(columns)})`)
        .run(...rowValues(rewrite)))).toMatch(GUARDED);
      expect(snapshot(table)).toEqual(before);
    });

    it('INSERT OR REPLACE cannot displace a row by naming its rowid', () => {
      const before = snapshot(table);
      const victim = one(`SELECT rowid AS _rowid FROM ${table} WHERE id = ?`, id);
      expect(refusal(() => db.prepare(`INSERT OR REPLACE INTO ${table} (rowid, ${columns.join(', ')}) VALUES (?, ${placeholders(columns)})`)
        .run(victim._rowid, ...rowValues({ id: `${id}-intruder` })))).toMatch(GUARDED);
      expect(snapshot(table)).toEqual(before);
    });

    it.each(EVERY_CLAUSE)('%s over an existing id is refused by the guard', (_clause, sql) => {
      const before = snapshot(table);
      expect(refusal(() => db.prepare(sql(table, [...columns])).run(...rowValues()))).toMatch(GUARDED);
      expect(snapshot(table)).toEqual(before);
    });

    it('the adapter’s own write of an existing id still throws DuplicateRecordError', async () => {
      const write = {
        chain_relinks: () => adapter.storeRelink(makeRelink({ id })),
        chain_forks: () => adapter.storeFork(makeFork({ id })),
        chain_annotations: () => adapter.storeAnnotation(makeAnnotation({ id })),
      }[table];
      await expect(write()).rejects.toBeInstanceOf(DuplicateRecordError);
      await expect(write()).rejects.toMatchObject({ recordId: id });
    });
  });

  // These tables refuse every UPDATE, so a rowid cannot be moved on them either.
  it.each(['custody_entries', 'envelope_revisions', 'chain_relinks', 'chain_forks', 'chain_annotations'])(
    'UPDATE OR REPLACE cannot move a %s row to another rowid',
    (table) => {
      const before = snapshot(table);
      const [first, second] = before;
      const target = second ? second._rowid : 999999;
      expect(refusal(() => db.prepare(`UPDATE OR REPLACE ${table} SET rowid = ? WHERE rowid = ?`).run(target, first._rowid)))
        .toMatch(/UPDATE refused/);
      expect(snapshot(table)).toEqual(before);
    },
  );

  describe('a rowid is never negative', () => {
    // Each *_block_replace guard reads NEW.rowid as -1 when an insert names
    // no rowid. A row planted at -1 would make every later insert on its table
    // collide with it, under the wrong error.
    const plant: Record<(typeof APPEND_ONLY_TABLES)[number], () => unknown> = {
      envelopes: () => {
        const e = makeEnvelope({ evidenceId: 'ev-ghost', sequenceNumber: 3 });
        return db.prepare(`INSERT INTO envelopes (rowid, ${ENVELOPE_COLUMNS.join(', ')}) VALUES (-1, ${placeholders(ENVELOPE_COLUMNS)})`)
          .run('ev-ghost', JSON.stringify(e), e.payload.capturedAt, 0, e.payload.aiSystemId, e.integrity.canonicalDigest, 'default');
      },
      chains: () => db.prepare(`INSERT INTO chains (rowid, chain_id, status, created_at) VALUES (-1, 'chain-ghost', 'active', ?)`)
        .run('2026-09-26T12:00:00.000Z'),
      envelope_revisions: () => db.prepare(`INSERT INTO envelope_revisions (rowid, ${REVISION_COLUMNS.join(', ')}) VALUES (-1, ${placeholders(REVISION_COLUMNS)})`)
        .run('ghost', 0, hex('ghost'), null, '2026-09-26T12:00:00.000Z', 'capture', 'mallory'),
      custody_entries: () => insertCustodyAt(-1, nextCustodyRow())(),
      chain_annotations: () => db.prepare(`INSERT INTO chain_annotations (rowid, ${ANNOTATION_COLUMNS.join(', ')}) VALUES (-1, ${placeholders(ANNOTATION_COLUMNS)})`)
        .run('ann-ghost', 'inc-ghost', '[]', '2026-09-26T12:00:00.000Z', 'mallory', 'ghost', '{}'),
      chain_relinks: () => db.prepare(`INSERT INTO chain_relinks (rowid, ${RELINK_COLUMNS.join(', ')}) VALUES (-1, ${placeholders(RELINK_COLUMNS)})`)
        .run('rlk-ghost', 'inc-ghost', '2026-09-26T12:00:00.000Z', 'mallory', 1, 2, '[]'),
      chain_forks: () => db.prepare(`INSERT INTO chain_forks (rowid, ${FORK_COLUMNS.join(', ')}) VALUES (-1, ${placeholders(FORK_COLUMNS)})`)
        .run('f-ghost', 'inc-ghost', '2026-09-26T12:00:00.000Z', 'mallory', 'ghost', 'chain-a', 'chain-g', 1, 1, 1),
    };
    /** The adapter's next write to each table, which a plant at -1 would have refused. */
    const nextWrite: Record<(typeof APPEND_ONLY_TABLES)[number], () => Promise<unknown>> = {
      envelopes: () => adapter.store(makeEnvelope({ evidenceId: 'ev-3', sequenceNumber: 3 })),
      envelope_revisions: () => adapter.store(makeEnvelope({ evidenceId: 'ev-3', sequenceNumber: 3 })),
      chains: () => adapter.storeChain({ chainId: 'brand-new', status: 'active', createdAt: '2026-09-26T12:00:00.000Z' }),
      custody_entries: () => adapter.appendCustodyEntry('ev-2', {
        timestamp: '2026-09-26T11:00:00.000Z', actor: 'admin@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
      }),
      chain_annotations: () => adapter.storeAnnotation(makeAnnotation({ id: 'ann-2' })),
      chain_relinks: () => adapter.storeRelink(makeRelink({ id: 'rlk-2' })),
      chain_forks: () => adapter.storeFork(makeFork({ id: 'f2' })),
    };

    it.each(APPEND_ONLY_TABLES)('%s refuses a row at rowid -1, and the adapter’s next write goes through', async (table) => {
      const before = snapshot(table);
      expect(refusal(plant[table])).toMatch(NEGATIVE_ROWID);
      expect(snapshot(table)).toEqual(before);
      await nextWrite[table]();
      expect(snapshot(table).length).toBeGreaterThan(before.length);
    });
  });

  describe('the SDK’s own writes go through', () => {
    it('store, relink, attestation retry, custody appends, chain registration and sealing, recovery records', async () => {
      // beforeEach stored two records, relinked one, registered and sealed a
      // chain, registered a second, and stored an annotation and a fork.
      expect((await adapter.listEnvelopeRevisions('ev-2')).map((r) => [r.revisionNo, r.cause])).toEqual([
        [0, 'capture'],
        [1, 'relink'],
      ]);
      expect((await adapter.retrieve('ev-2'))!.integrity.chainLink).toBe(RELINKED_LINK);
      expect(await adapter.listCustodyEntries('ev-2')).toHaveLength(1);
      expect((await adapter.getChain('chain-s'))!.status).toBe('sealed');

      await adapter.updateAttestation('ev-1', { rfc3161Token: 'tok' } as never, 'partial');
      await adapter.appendCustodyEntry('ev-2', {
        timestamp: '2026-09-26T11:00:00.000Z', actor: 'admin@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
      });
      await adapter.store(makeEnvelope({ evidenceId: 'ev-3', sequenceNumber: 3 }));
      await adapter.storeChain({ chainId: 'chain-t', status: 'active', createdAt: '2026-09-26T12:00:00.000Z' });
      await adapter.sealChain('chain-a', '2026-09-26T12:30:00.000Z');
      await adapter.storeAnnotation(makeAnnotation({ id: 'ann-2' }));
      await adapter.storeRelink(makeRelink({ id: 'rlk-2' }));
      await adapter.storeFork(makeFork({ id: 'f2' }));

      expect((await adapter.listEnvelopeRevisions('ev-1')).map((r) => r.cause)).toEqual(['capture', 'attestation_retry']);
      expect(await adapter.listCustodyEntries('ev-2')).toHaveLength(2);
      expect(await adapter.getCaptureDigests(['ev-3'])).toEqual({ 'ev-3': hex('ev-3') });
      expect((await adapter.getChain('chain-t'))!.status).toBe('active');
      expect((await adapter.getChain('chain-a'))!.status).toBe('sealed');
      expect((await adapter.getAnnotation('ann-2'))!.id).toBe('ann-2');
      expect((await adapter.getRelink('rlk-2'))!.id).toBe('rlk-2');
      expect((await adapter.getFork('f2'))!.id).toBe('f2');
    });

    it('an idempotent capture claims once and replays', async () => {
      const envelope = makeEnvelope({ evidenceId: 'ev-idem', sequenceNumber: 3 });
      const idempotency = { key: 'key-1', fingerprint: 'fp-1' };
      expect((await adapter.storeIdempotent(envelope, undefined, { idempotency })).kind).toBe('claimed');
      expect((await adapter.storeIdempotent(envelope, undefined, { idempotency })).kind).toBe('replay');
    });

    describe('the demo delete hook', () => {
      const savedValve = process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
      afterEach(() => {
        if (savedValve === undefined) delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
        else process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = savedValve;
      });

      it('a record deleted and re-stored under its id keeps its capture revision', async () => {
        process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
        const spy = jest.spyOn(console, 'error').mockImplementation(() => { /* the armed line */ });
        try {
          await adapter.armDemoTamperHooks();
        } finally {
          spy.mockRestore();
        }
        const original = (await adapter.retrieve('ev-1'))!;
        await adapter.deleteEnvelopeForDemo('ev-1');
        const tampered = hex('tampered-ev-1');
        await adapter.store({
          ...original,
          payload: { ...original.payload, reason: 'tampered' },
          integrity: { ...original.integrity, canonicalDigest: tampered },
        });

        expect((await adapter.retrieve('ev-1'))!.integrity.canonicalDigest).toBe(tampered);
        // Revision 0 still names what the record was captured as: the re-store
        // wrote no capture revision over it.
        expect(await adapter.getCaptureDigests(['ev-1'])).toEqual({ 'ev-1': hex('ev-1') });
        expect((await adapter.listEnvelopeRevisions('ev-1')).map((r) => [r.revisionNo, r.canonicalDigest])).toEqual([
          [0, hex('ev-1')],
        ]);
      });
    });
  });

  it('a store written before the guards existed gets them when it is opened', async () => {
    await adapter.close();
    const raw = new Database(dbPath);
    try {
      for (const name of GUARDS) raw.exec(`DROP TRIGGER ${name}`);
    } finally {
      raw.close();
    }

    adapter = new SqliteStorageAdapter(dbPath);
    db = (adapter as unknown as { db: Db }).db;
    const installed = all(
      `SELECT name FROM sqlite_master WHERE type = 'trigger' AND name IN (${placeholders(GUARDS)}) ORDER BY name`,
      ...GUARDS,
    ).map((r) => r.name);
    expect(installed).toEqual(GUARDS);
    const row = one('SELECT * FROM chains WHERE chain_id = ?', 'chain-s');
    expect(refusal(() => db.prepare(
      `INSERT OR REPLACE INTO chains (${CHAIN_COLUMNS.join(', ')}) VALUES (${CHAIN_COLUMNS.map(() => '?').join(', ')})`,
    ).run(...CHAIN_COLUMNS.map((c) => (c === 'status' ? 'active' : c === 'sealed_at' ? null : row[c]))))).toMatch(GUARDED);
    expect(refusal(() => db.prepare('UPDATE envelopes SET rowid = 999999 WHERE evidence_id = ?').run('ev-1'))).toMatch(ROWID_FROZEN);
  });
});
