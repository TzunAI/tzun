/**
 * A store written by a pre-0.4.6 build gets `tamper_incidents.last_observed_at`
 * added in place.
 *
 * `CREATE TABLE IF NOT EXISTS` skips a table that already exists, so without the
 * upgrade the column is simply absent on every store anyone is already running,
 * and the first `storeIncident()` after the update fails on it — the scanner then
 * finds tampering and cannot record that it did. That is the same class of hard
 * break `evolveLegacyChainState` exists for, so it gets the same treatment.
 *
 * Nothing is backfilled. A pass that ran BEFORE the upgrade recorded no
 * observation, and inventing one would claim a scan saw a finding at a time no
 * scan was looking; the old rows stay NULL and are counted in neither direction
 * until a pass observes their finding for real.
 *
 * Each leg builds the OLD table shape by hand, then opens the adapter over it.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import Database from 'better-sqlite3';
import { Client } from 'pg';
import { TamperIncident } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';

const OLD_COLUMNS =
  'id, detected_at, severity, type, affected_records, affected_sequence_range, ' +
  'details, status, resolved_at, resolved_by, resolution_notes';

const incident = (id: string): TamperIncident => ({
  id,
  detectedAt: '2026-09-19T10:00:00.000Z',
  severity: 'critical',
  type: 'digest_mismatch',
  affectedRecords: ['ev-1'],
  details: 'Digest mismatch on ev-1',
  status: 'open',
  lastObservedAt: '2026-09-19T10:00:00.000Z',
});

describe('sqlite: last_observed_at is added to a pre-0.4.6 tamper_incidents', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-obs-upgrade-'));
    file = path.join(dir, 'old.db');
    // The old table shape, with one incident already in it.
    const db = new Database(file);
    db.exec(`
      CREATE TABLE tamper_incidents (
        id TEXT PRIMARY KEY,
        detected_at TEXT NOT NULL,
        severity TEXT NOT NULL,
        type TEXT NOT NULL,
        affected_records TEXT NOT NULL,
        affected_sequence_range TEXT,
        details TEXT NOT NULL,
        status TEXT NOT NULL,
        resolved_at TEXT,
        resolved_by TEXT,
        resolution_notes TEXT
      );
    `);
    db.prepare(
      `INSERT INTO tamper_incidents (${OLD_COLUMNS})
       VALUES ('inc-old', '2026-09-01T00:00:00.000Z', 'critical', 'digest_mismatch',
               '["ev-1"]', NULL, 'from an earlier build', 'resolved', NULL, NULL, NULL)`,
    ).run();
    db.close();
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('adds the column, keeps the old row, and leaves its observation NULL', async () => {
    const storage = new SqliteStorageAdapter(file);
    try {
      const [old] = await storage.listIncidents();
      expect(old.id).toBe('inc-old');
      expect(old.details).toBe('from an earlier build');
      // Not backfilled: no scan ever observed this finding.
      expect(old.lastObservedAt).toBeUndefined();
    } finally {
      await storage.close();
    }
  });

  it('can store an incident afterwards — which is what fails without the upgrade', async () => {
    const storage = new SqliteStorageAdapter(file);
    try {
      await expect(storage.storeIncident(incident('inc-new'))).resolves.toBeUndefined();
      const stored = await storage.getIncident('inc-new');
      expect(stored!.lastObservedAt).toBe('2026-09-19T10:00:00.000Z');

      await storage.recordIncidentObservation('inc-old', '2026-09-19T11:00:00.000Z');
      const stamped = await storage.getIncident('inc-old');
      expect(stamped!.lastObservedAt).toBe('2026-09-19T11:00:00.000Z');
      // The stamp moves that column and nothing else.
      expect(stamped!.status).toBe('resolved');
    } finally {
      await storage.close();
    }
  });

  it('is a no-op on a store that already has the column', async () => {
    const first = new SqliteStorageAdapter(file);
    await first.close();
    const second = new SqliteStorageAdapter(file);
    try {
      await second.storeIncident(incident('inc-second-open'));
      expect((await second.getIncident('inc-second-open'))!.lastObservedAt).toBe(
        '2026-09-19T10:00:00.000Z',
      );
    } finally {
      await second.close();
    }
  });
});

// A schema of this file's own, created before its first case and dropped after
// its last.
const schema = pgSuiteSchema('obs_upgrade');

(PG_TESTS_ENABLED ? describe : describe.skip)(
  'postgres: last_observed_at is added to a pre-0.4.6 tamper_incidents',
  () => {
    // Connected into the schema, so the old table below is built there.
    let admin: Client;
    let storage: PostgresStorageAdapter;

    beforeAll(async () => {
      admin = new Client({ connectionString: schema.url });
      await admin.connect();
      await admin.query(`
        CREATE TABLE tamper_incidents (
          id TEXT PRIMARY KEY,
          detected_at TIMESTAMPTZ NOT NULL,
          severity TEXT NOT NULL,
          type TEXT NOT NULL,
          affected_records JSONB NOT NULL,
          affected_sequence_range JSONB,
          details TEXT NOT NULL,
          status TEXT NOT NULL,
          resolved_at TIMESTAMPTZ,
          resolved_by TEXT,
          resolution_notes TEXT
        )
      `);
      await admin.query(
        `INSERT INTO tamper_incidents (${OLD_COLUMNS})
         VALUES ('inc-old', '2026-09-01T00:00:00.000Z', 'critical', 'digest_mismatch',
                 '["ev-1"]'::jsonb, NULL, 'from an earlier build', 'resolved', NULL, NULL, NULL)`,
      );

      storage = new PostgresStorageAdapter(schema.url);
      await storage.ensureTables();
    });

    afterAll(async () => {
      await storage?.close();
      await admin.end();
    });

    it('adds the column, keeps the old row, and leaves its observation NULL', async () => {
      const [old] = await storage.listIncidents();
      expect(old.id).toBe('inc-old');
      expect(old.details).toBe('from an earlier build');
      expect(old.lastObservedAt).toBeUndefined();
    });

    it('can store an incident afterwards, and stamps an observation without touching the rest', async () => {
      await expect(storage.storeIncident(incident('inc-new'))).resolves.toBeUndefined();
      expect((await storage.getIncident('inc-new'))!.lastObservedAt).toBe('2026-09-19T10:00:00.000Z');

      await storage.recordIncidentObservation('inc-old', '2026-09-19T11:00:00.000Z');
      const stamped = await storage.getIncident('inc-old');
      expect(stamped!.lastObservedAt).toBe('2026-09-19T11:00:00.000Z');
      expect(stamped!.status).toBe('resolved');
    });

    it('refuses to stamp an incident that does not exist', async () => {
      await expect(
        storage.recordIncidentObservation('inc-absent', '2026-09-19T11:00:00.000Z'),
      ).rejects.toThrow(/not found/);
    });
  },
);
