/**
 * The SQLite `envelopes` table is append-only in the database,
 * as its sibling tables (custody_entries, envelope_revisions, credential_events)
 * and the SDK-Postgres `envelopes` table already are.
 *
 * What is frozen matches the Postgres trigger: the payload (every field of it,
 * `schemaVersion` included), `integrity.canonicalDigest`, the evidence_id,
 * digest, captured_at, chain_id and ai_system_id columns, and the custody chain
 * except for appends. DELETE is refused, qualified or not. The SDK's own
 * writes — attestation retry, relink's chain-link repair, custody appends —
 * still go through, and so does the demo's delete hook, which steps around the
 * trigger only after the arming guard has passed.
 *
 * Every attack is a raw statement on the adapter's own connection, the way an
 * insider with the file open would issue it.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { EvidenceEnvelope } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { DemoTamperGuardError } from '../../src/storage/demo-tamper-guard';
import { makeEnvelope } from './storage-conformance/fixtures';

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

describe('SQLite envelopes are append-only in the database', () => {
  let dir: string;
  let adapter: SqliteStorageAdapter;
  let db: Db;

  beforeEach(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-'));
    adapter = new SqliteStorageAdapter(path.join(dir, 'evidence.db'));
    db = (adapter as unknown as { db: Db }).db;
    await adapter.store(makeEnvelope({ evidenceId: 'ev-1', sequenceNumber: 1 }));
    await adapter.store(makeEnvelope({ evidenceId: 'ev-2', sequenceNumber: 1 }), 'chain-a');
  });

  afterEach(async () => {
    await adapter.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const stored = (id: string): EvidenceEnvelope =>
    JSON.parse((db.prepare('SELECT envelope FROM envelopes WHERE evidence_id = ?').get(id) as { envelope: string }).envelope);

  /** Rewrite the stored JSON blob of `id` with a raw UPDATE. */
  const rewrite = (id: string, mutate: (e: EvidenceEnvelope & Record<string, unknown>) => void) => () => {
    const envelope = stored(id) as EvidenceEnvelope & Record<string, unknown>;
    mutate(envelope);
    db.prepare('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?').run(JSON.stringify(envelope), id);
  };

  describe('the payload and the digest are frozen', () => {
    const payloadEdits: Array<[string, (e: EvidenceEnvelope) => void]> = [
      ['reason', (e) => { e.payload.reason = 'rewritten'; }],
      ['schemaVersion', (e) => { (e.payload as { schemaVersion: string }).schemaVersion = 'v9.9'; }],
      ['sequenceNumber', (e) => { e.payload.sequenceNumber = 7; }],
      ['aiOutput (nested)', (e) => { (e.payload.aiOutput as Record<string, unknown>).confidence = 0.1; }],
      ['a key added', (e) => { (e.payload as unknown as Record<string, unknown>).extra = true; }],
    ];
    it.each(payloadEdits)('refuses a rewrite of payload.%s', (_field, mutate) => {
      const before = stored('ev-1');
      expect(refusal(rewrite('ev-1', mutate))).toMatch(/payload is immutable/);
      expect(stored('ev-1')).toEqual(before);
    });

    it('refuses a rewrite of integrity.canonicalDigest', () => {
      expect(refusal(rewrite('ev-1', (e) => { e.integrity.canonicalDigest = 'sha256:' + 'f'.repeat(64); })))
        .toMatch(/canonicalDigest is immutable/);
    });

    it('refuses dropping the payload or the whole envelope shape', () => {
      expect(refusal(rewrite('ev-1', (e) => { delete (e as Partial<EvidenceEnvelope>).payload; })))
        .toMatch(/payload is immutable/);
    });
  });

  describe('the indexed columns are frozen', () => {
    const columns: Array<[string, string, unknown]> = [
      ['evidence_id', 'UPDATE envelopes SET evidence_id = ? WHERE evidence_id = ?', 'ev-renamed'],
      ['digest', 'UPDATE envelopes SET digest = ? WHERE evidence_id = ?', 'sha256:' + '0'.repeat(64)],
      ['captured_at', 'UPDATE envelopes SET captured_at = ? WHERE evidence_id = ?', '2020-01-01T00:00:00.000Z'],
      ['captured_at_ms', 'UPDATE envelopes SET captured_at_ms = ? WHERE evidence_id = ?', 0],
      ['chain_id', 'UPDATE envelopes SET chain_id = ? WHERE evidence_id = ?', 'stolen'],
      ['ai_system_id', 'UPDATE envelopes SET ai_system_id = ? WHERE evidence_id = ?', 'other-system'],
    ];
    it.each(columns)('refuses a change to %s', (column, sql, value) => {
      expect(refusal(() => db.prepare(sql).run(value, 'ev-1'))).toMatch(new RegExp(`${column.replace('_ms', '')}.* is immutable`));
    });
  });

  describe('the custody chain only grows', () => {
    it('refuses emptying it', () => {
      expect(refusal(rewrite('ev-1', (e) => { e.custodyChain = []; }))).toMatch(/custodyChain is append-only/);
    });

    it('refuses removing it', () => {
      expect(refusal(rewrite('ev-1', (e) => { delete (e as Partial<EvidenceEnvelope>).custodyChain; })))
        .toMatch(/custodyChain is append-only/);
    });

    it('refuses rewriting an existing entry', () => {
      expect(refusal(rewrite('ev-1', (e) => { e.custodyChain[0].actor = 'mallory@acme.example'; })))
        .toMatch(/custodyChain is append-only/);
    });

    it('refuses adding a key to an existing entry in place', () => {
      expect(refusal(rewrite('ev-1', (e) => {
        (e.custodyChain[0] as unknown as Record<string, unknown>).entryHash = 'a'.repeat(64);
      }))).toMatch(/custodyChain is append-only/);
    });

    it('refuses replacing the chain with a non-array', () => {
      expect(refusal(rewrite('ev-1', (e) => { (e as unknown as Record<string, unknown>).custodyChain = { 0: e.custodyChain[0] }; })))
        .toMatch(/custodyChain is append-only/);
    });

    it('accepts an appended unhashed entry', () => {
      rewrite('ev-1', (e) => {
        e.custodyChain.push({ timestamp: '2026-04-04T12:00:00.000Z', actor: 'admin@acme.example', action: 'reviewed', systemId: 'x' });
      })();
      expect(stored('ev-1').custodyChain).toHaveLength(2);
    });
  });

  describe('rows are never deleted', () => {
    it('refuses DELETE of one record', () => {
      expect(refusal(() => db.prepare('DELETE FROM envelopes WHERE evidence_id = ?').run('ev-1')))
        .toMatch(/cannot be deleted/);
      expect(stored('ev-1').payload.evidenceId).toBe('ev-1');
    });

    it('refuses an unqualified DELETE FROM envelopes, and keeps every row', () => {
      expect(refusal(() => db.prepare('DELETE FROM envelopes').run())).toMatch(/cannot be deleted/);
      expect((db.prepare('SELECT COUNT(*) AS n FROM envelopes').get() as { n: number }).n).toBe(2);
    });
  });

  describe('the SDK’s own writes still go through', () => {
    it('attestation retry replaces nonRepudiation and attestationStatus', async () => {
      await adapter.updateAttestation('ev-1', { rfc3161Token: 'tok' } as never, 'partial');
      const after = stored('ev-1');
      expect(after.attestationStatus).toBe('partial');
      expect((after.nonRepudiation as Record<string, unknown>).rfc3161Token).toBe('tok');
    });

    it('relink rewrites the chain link', async () => {
      await adapter.updateEnvelopeChainLink('ev-2', 'sha256:' + '1'.repeat(64));
      expect(stored('ev-2').integrity.chainLink).toBe('sha256:' + '1'.repeat(64));
    });

    it('a custody append grows the chain', async () => {
      await adapter.appendCustodyEntry('ev-1', {
        timestamp: '2026-04-04T12:00:00.000Z', actor: 'admin@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
      });
      expect(stored('ev-1').custodyChain).toHaveLength(2);
    });
  });

  describe('the demo delete hook', () => {
    const savedValve = process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
    afterEach(() => {
      if (savedValve === undefined) delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
      else process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = savedValve;
    });

    async function arm(): Promise<void> {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => { /* armed / refused lines */ });
      try {
        await adapter.armDemoTamperHooks();
      } finally {
        spy.mockRestore();
      }
    }

    it('unarmed, it throws and deletes nothing', async () => {
      delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
      await arm(); // a populated, unsentineled store: refused
      await expect(adapter.deleteEnvelopeForDemo('ev-1')).rejects.toThrow(DemoTamperGuardError);
      expect(stored('ev-1').payload.evidenceId).toBe('ev-1');
    });

    it('armed, it deletes past the trigger, the demo can re-store, and the trigger is back afterwards', async () => {
      process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
      await arm();
      const original = stored('ev-1');

      await adapter.deleteEnvelopeForDemo('ev-1');
      expect(await adapter.retrieve('ev-1')).toBeNull();

      // The demo's rewrite pattern: delete, then store a replacement.
      await adapter.store({ ...original, payload: { ...original.payload, reason: 'tampered' } });
      expect(stored('ev-1').payload.reason).toBe('tampered');

      // The bypass lasted exactly one statement's transaction.
      expect(refusal(() => db.prepare('DELETE FROM envelopes WHERE evidence_id = ?').run('ev-2')))
        .toMatch(/cannot be deleted/);
      const triggers = (db.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'envelopes' ORDER BY name",
      ).all() as Array<{ name: string }>).map((r) => r.name);
      expect(triggers).toEqual([
        'envelopes_block_delete',
        'envelopes_block_low_rowid',
        'envelopes_block_negative_rowid',
        'envelopes_block_replace',
        'envelopes_block_rowid_change',
        'envelopes_enforce_immutable',
        'envelopes_evidence_log_append',
      ]);
    });
  });
});
