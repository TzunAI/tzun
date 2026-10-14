/**
 * Upgrading a store that already has records (Tree §5.2).
 *
 * The migration that installs the evidence-log trigger runs in one
 * transaction: mint the identity, create each existing chain's log, backfill
 * its leaves from the stored records in sequence order, and only then create
 * the density trigger and the trigger on `envelopes`. Without the backfill,
 * the first capture after the upgrade would fail the density check.
 *
 * Every case starts from a store as SDK 0.5.0 left it: records captured on
 * two chains through `Tzun.capture()`, then everything the log schema adds
 * removed (tests/ts/helpers/store-schema.ts). The first case pins that the
 * result is exactly the schema the 0.5.0 code creates, so the store being
 * upgraded is a 0.5.0 store and not an approximation of one.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { EvidenceEnvelope, StorageAdapter } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import {
  EvidenceLogRefusalError,
  LogStore,
  logMigrationTestHooks,
  logStoreFor,
} from '../../src/storage/log-store';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { LogBackend, RawDb, logBackends, refusal } from './helpers/log-store-backends';
import {
  LATER_GUARDS_POSTGRES,
  LATER_GUARDS_SQLITE,
  LATER_INDEXES_POSTGRES,
  REMOVED_FUNCTIONS_POSTGRES,
  REWRITTEN_FUNCTIONS_POSTGRES,
  postgresSchemaSnapshot,
  sqliteSchemaSnapshot,
  stripLogSchemaPostgres,
  stripLogSchemaSqlite,
} from './helpers/store-schema';

const REPO = join(__dirname, '..', '..');
const SNAPSHOT_DIR = join(REPO, 'tests', 'fixtures', 'store-schema-0.5.0');
const RECORDS = { default: 300, 'tenant-b': 200 } as const;
type Chain = keyof typeof RECORDS;

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

/** Capture `RECORDS` through the SDK, one instance per chain, then strip the store back to 0.5.0. */
async function write050Store(backend: LogBackend): Promise<void> {
  await backend.fresh();
  const target = backend.name === 'sqlite' ? { dbPath: backend.location() } : { dbUrl: backend.location() };
  for (const [chainId, count] of Object.entries(RECORDS)) {
    const tzun = await Tzun.init({ mode: 'dev', ...target, chainId, verifyReads: false });
    for (let i = 1; i <= count; i++) {
      const r = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { chain: chainId, i },
        action: 'approved',
        reason: `record ${i}`,
        aiSystemId: 'upgrade-suite',
      });
      if (!r.stored) throw new Error(`capture ${chainId}#${i} was not stored: ${JSON.stringify(r.failure)}`);
    }
    await tzun.close();
  }
  const { raw, close } = await backend.rawOnly();
  try {
    if (raw.sqlite) stripLogSchemaSqlite(raw.sqlite);
    else await stripLogSchemaPostgres(raw.pg!);
  } finally {
    await close();
  }
}

/** The records of a chain, by sequence number, read without the adapter. */
async function recordsOf(raw: RawDb, backend: LogBackend, chainId: string): Promise<Array<{ seq: number; digest: string; id: string }>> {
  const rows = await raw.all<{ id: string; seq: number | string; digest: string }>(
    backend.name === 'sqlite'
      ? "SELECT evidence_id AS id, json_extract(envelope, '$.payload.sequenceNumber') AS seq, json_extract(envelope, '$.integrity.canonicalDigest') AS digest FROM envelopes WHERE chain_id = ?"
      : "SELECT evidence_id AS id, (envelope->'payload'->>'sequenceNumber')::int AS seq, envelope->'integrity'->>'canonicalDigest' AS digest FROM envelopes WHERE chain_id = ?",
    [chainId],
  );
  return rows.map((r) => ({ id: r.id, seq: Number(r.seq), digest: r.digest })).sort((a, b) => a.seq - b.seq);
}

/** Delete one record past the append-only guard, as only a table owner can. */
async function deleteRecord(raw: RawDb, backend: LogBackend, evidenceId: string): Promise<void> {
  if (backend.name === 'sqlite') {
    await raw.run('DROP TRIGGER envelopes_block_delete');
    await raw.run('DELETE FROM envelopes WHERE evidence_id = ?', [evidenceId]);
    await raw.run(`CREATE TRIGGER envelopes_block_delete BEFORE DELETE ON envelopes
                   BEGIN SELECT RAISE(ABORT, 'envelopes rows cannot be deleted (append-only evidence)'); END`);
  } else {
    await raw.run('BEGIN');
    await raw.run("SET LOCAL session_replication_role = 'replica'");
    await raw.run('DELETE FROM envelopes WHERE evidence_id = ?', [evidenceId]);
    await raw.run('COMMIT');
  }
}

/** Store the next record of `chainId` exactly as capture does: at last + 1, against the live head. */
async function appendNext(adapter: StorageAdapter, chainId: string, label: string): Promise<EvidenceEnvelope> {
  const sequence = await adapter.getLastSequence(chainId);
  const digest = await adapter.getLastDigest(chainId);
  const env: EvidenceEnvelope = {
    envelopeVersion: 'e1',
    payload: {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: label,
      schemaVersion: 'v1.0',
      aiSystemId: 'upgrade-suite',
      aiOutput: { after: 'upgrade' },
      action: 'approved',
      reason: 'first record after the upgrade',
      capturedAt: new Date().toISOString(),
      sequenceNumber: sequence + 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: hex(label), chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
  await adapter.store(env, chainId, { expectChainHead: { sequence, digest } });
  return env;
}

const backends = logBackends('log_upgrade');

describe.each(backends.map((b) => [b.name, b] as const))('upgrading a 0.5.0 store on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(180_000);

  beforeEach(async () => {
    logMigrationTestHooks.afterBackfill = undefined;
    await write050Store(backend);
  });

  afterEach(() => {
    logMigrationTestHooks.afterBackfill = undefined;
  });

  afterAll(async () => backend.dispose());

  /**
   * The store is the 0.5.0 store. `openedSince`: an open ran since the strip.
   * The adapter's own DDL, which installs the SQLite insert guards
   *, the Postgres `created_at` index and the Postgres guards on
   * `custody_entries` and `credential_events`, and rewrites the
   * Postgres functions that read tables by the trigger table's schema
   *, commits before the evidence-log migration starts, so they
   * are there whatever became of the migration; they are checked apart from the
   * snapshot.
   */
  async function snapshotEquals050(openedSince = false): Promise<void> {
    const { raw, close } = await backend.rawOnly();
    try {
      if (raw.sqlite) {
        const expected = JSON.parse(readFileSync(join(SNAPSHOT_DIR, 'sqlite.json'), 'utf8')).objects;
        let actual = sqliteSchemaSnapshot(raw.sqlite);
        if (openedSince) {
          const isGuard = (name: string): boolean => (LATER_GUARDS_SQLITE as readonly string[]).includes(name);
          expect(actual.filter((o) => isGuard(o.name)).map((o) => o.name).sort()).toEqual([...LATER_GUARDS_SQLITE].sort());
          actual = actual.filter((o) => !isGuard(o.name));
        }
        expect(actual).toEqual(expected);
      } else {
        const client = raw.pg!;
        const schema = (await client.query<{ s: string }>('SELECT current_schema() AS s')).rows[0].s;
        const { generatedFrom: _from, ...expected } = JSON.parse(readFileSync(join(SNAPSHOT_DIR, 'postgres.json'), 'utf8'));
        const actual = await postgresSchemaSnapshot(client, schema);
        if (openedSince) {
          const isLater = (name: string): boolean => (LATER_INDEXES_POSTGRES as readonly string[]).includes(name);
          expect(actual.indexes.filter((i) => isLater(i.name)).map((i) => i.name).sort()).toEqual([...LATER_INDEXES_POSTGRES].sort());
          actual.indexes = actual.indexes.filter((i) => !isLater(i.name));
          const triggers = LATER_GUARDS_POSTGRES.map((g) => g.trigger as string);
          const fns = LATER_GUARDS_POSTGRES.map((g) => g.fn as string);
          expect(actual.triggers.filter((t) => triggers.includes(t.name)).map((t) => t.name).sort()).toEqual([...triggers].sort());
          expect(actual.functions.filter((f) => fns.includes(f.name)).map((f) => f.name).sort()).toEqual([...fns].sort());
          actual.triggers = actual.triggers.filter((t) => !triggers.includes(t.name));
          actual.functions = actual.functions.filter((f) => !fns.includes(f.name));
          const rewritten = REWRITTEN_FUNCTIONS_POSTGRES as readonly string[];
          const removed = REMOVED_FUNCTIONS_POSTGRES as readonly string[];
          expect(actual.functions.filter((f) => rewritten.includes(f.name)).map((f) => f.name).sort()).toEqual([...rewritten].sort());
          expect(actual.functions.filter((f) => removed.includes(f.name))).toEqual([]);
          actual.functions = actual.functions.filter((f) => !rewritten.includes(f.name));
          expected.functions = expected.functions.filter(
            (f: { name: string }) => !rewritten.includes(f.name) && !removed.includes(f.name),
          );
        }
        expect(actual).toEqual(expected);
      }
    } finally {
      await close();
    }
  }

  it('the store being upgraded is exactly the schema 0.5.0 creates', async () => {
    await snapshotEquals050();
  });

  it('upgrades in place: identity minted, each chain backfilled in sequence order, and the next capture lands at leaf_index = last_sequence', async () => {
    const opened = await backend.open();
    const adapter = opened.adapter as StorageAdapter;
    const logs: LogStore = logStoreFor(opened.adapter)!;
    try {
      const identity = await logs.getStoreIdentity();
      expect(identity.storeId).toMatch(/^[0-9a-f]{32}$/);

      const coverage = await logs.getEvidenceLogCoverage();
      expect(coverage.map((c) => [c.chainId, c.size, c.leafCount, c.captured, c.backfilled, c.lastSequence, c.missing])).toEqual([
        ['default', 300, 300, 0, 300, 300, []],
        ['tenant-b', 200, 200, 0, 200, 200, []],
      ]);

      for (const chainId of Object.keys(RECORDS) as Chain[]) {
        const log = (await logs.getEvidenceLog(chainId))!;
        const leaves = await logs.listLogLeaves(log.logId, 0, 1_000);
        const records = await recordsOf(opened.raw, backend, chainId);
        expect(leaves.map((l) => [l.leafIndex, l.leafDigest, l.sourceRef, l.source])).toEqual(
          records.map((r) => [r.seq - 1, r.digest, r.id, 'backfill']),
        );

        const lastSequence = await adapter.getLastSequence(chainId);
        const next = await appendNext(adapter, chainId, `after-upgrade-${chainId}`);
        expect(await logs.getEvidenceLogPosition(next.payload.evidenceId)).toMatchObject({
          chainId,
          leafIndex: lastSequence,
          source: 'capture',
        });
      }
    } finally {
      await opened.close();
    }

    // And through the SDK, on each chain.
    const target = backend.name === 'sqlite' ? { dbPath: backend.location() } : { dbUrl: backend.location() };
    for (const chainId of Object.keys(RECORDS) as Chain[]) {
      const tzun = await Tzun.init({ mode: 'dev', ...target, chainId, verifyReads: false });
      const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { via: 'sdk' }, action: 'approved', reason: 'after', aiSystemId: 'upgrade-suite' });
      await tzun.close();
      expect(r.stored).toBe(true);
      expect(r.envelope.payload.sequenceNumber).toBe(RECORDS[chainId] + 2);
      const reader = await backend.open();
      try {
        expect(await logStoreFor(reader.adapter)!.getEvidenceLogPosition(r.envelope.payload.evidenceId)).toMatchObject({
          leafIndex: RECORDS[chainId] + 1,
          leafDigest: r.envelope.integrity.canonicalDigest,
          source: 'capture',
        });
      } finally {
        await reader.close();
      }
    }
  });

  it('re-running the migration is a no-op', async () => {
    const first = await backend.open();
    const logs = logStoreFor(first.adapter)!;
    const identity = await logs.getStoreIdentity();
    const log = (await logs.getEvidenceLog('default'))!;
    const leaves = await logs.listLogLeaves(log.logId, 0, 1_000);
    const logList = (await logs.listLogs()).map((l) => [l.logId, l.origin, l.createdAt]);
    await first.close();

    for (let i = 0; i < 2; i++) {
      const again = await backend.open();
      const logsAgain = logStoreFor(again.adapter)!;
      expect(await logsAgain.getStoreIdentity()).toEqual(identity);
      expect((await logsAgain.listLogs()).map((l) => [l.logId, l.origin, l.createdAt])).toEqual(logList);
      expect(await logsAgain.listLogLeaves(log.logId, 0, 1_000)).toEqual(leaves);
      await again.close();
    }
  });

  it('a migration that fails part-way leaves nothing behind, and the next open runs it again from the start', async () => {
    logMigrationTestHooks.afterBackfill = () => {
      throw new Error('interrupted after the backfill');
    };
    await refusal(backend.open(), /interrupted after the backfill/);
    await snapshotEquals050(true);

    // A 0.5.0 writer is still running against the store: its next record lands, with no leaf.
    const { raw, close } = await backend.rawOnly();
    try {
      const late = {
        envelopeVersion: 'e1',
        payload: {
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          links: null,
          evidenceId: 'late-050', schemaVersion: 'v1.0', aiSystemId: 'upgrade-suite', aiOutput: {}, action: 'approved',
          reason: 'written by 0.5.0 during the failed upgrade', capturedAt: '2026-09-25T10:00:00.000Z',
          sequenceNumber: RECORDS.default + 1, contributions: null,
        },
        integrity: { canonicalDigest: hex('late-050'), chainLink: null },
        nonRepudiation: {}, custodyChain: [], attestationStatus: 'none',
      };
      await raw.run(
        backend.name === 'sqlite'
          ? 'INSERT INTO envelopes (evidence_id, envelope, captured_at, captured_at_ms, ai_system_id, digest, chain_id) VALUES (?, ?, ?, 0, ?, ?, ?)'
          : 'INSERT INTO envelopes (evidence_id, envelope, captured_at, ai_system_id, digest, chain_id) VALUES (?, ?::jsonb, ?, ?, ?, ?)',
        ['late-050', JSON.stringify(late), late.payload.capturedAt, 'upgrade-suite', hex('late-050'), 'default'],
      );
      await raw.run('UPDATE chain_state SET last_digest = ?, last_sequence = ? WHERE chain_id = ?', [hex('late-050'), RECORDS.default + 1, 'default']);
    } finally {
      await close();
    }

    logMigrationTestHooks.afterBackfill = undefined;
    const opened = await backend.open();
    try {
      const logs = logStoreFor(opened.adapter)!;
      expect(await logs.getEvidenceLogPosition('late-050')).toMatchObject({ leafIndex: RECORDS.default, source: 'backfill' });
      const next = await appendNext(opened.adapter as StorageAdapter, 'default', 'after-the-retry');
      expect((await logs.getEvidenceLogPosition(next.payload.evidenceId))!.leafIndex).toBe(RECORDS.default + 1);
    } finally {
      await opened.close();
    }
  });

  it('a process killed in the middle of the migration leaves nothing behind, and the next open completes it', async () => {
    const child = spawnSync(
      join(REPO, 'node_modules', '.bin', 'tsx'),
      [join(REPO, 'tests', 'ts', 'helpers', 'migration-crash-child.ts'), backend.name, backend.location()],
      { cwd: REPO, encoding: 'utf8', timeout: 120_000 },
    );
    expect(child.stdout).toContain('backfilled');
    expect(child.stdout).not.toContain('migration finished');
    // tsx runs the script in a node child of its own and reports that child's
    // SIGKILL as exit status 128 + 9.
    expect(child.signal === 'SIGKILL' || child.status === 137).toBe(true);
    await snapshotEquals050(true);

    const opened = await backend.open();
    try {
      const coverage = await logStoreFor(opened.adapter)!.getEvidenceLogCoverage();
      expect(coverage.map((c) => [c.chainId, c.backfilled, c.missing])).toEqual([
        ['default', 300, []],
        ['tenant-b', 200, []],
      ]);
      await appendNext(opened.adapter as StorageAdapter, 'tenant-b', 'after-the-crash');
    } finally {
      await opened.close();
    }
  });

  it('a chain that lost a record in the middle before its log existed backfills its dense prefix, and is refused new records', async () => {
    const { raw, close } = await backend.rawOnly();
    let records: Array<{ seq: number; digest: string; id: string }>;
    try {
      records = await recordsOf(raw, backend, 'default');
      await deleteRecord(raw, backend, records[149].id);
    } finally {
      await close();
    }
    const opened = await backend.open();
    try {
      const logs = logStoreFor(opened.adapter)!;
      const [coverage] = await logs.getEvidenceLogCoverage();
      // Leaves 0..148: the records before the hole. None after it, since a
      // log with a hole has no root that covers those leaves.
      expect(coverage).toMatchObject({
        chainId: 'default',
        size: 149,
        leafCount: 149,
        backfilled: 149,
        lastSequence: 300,
        missing: [{ from: 149, to: 299 }],
      });
      const leaves = await logs.listLogLeaves(coverage.logId, 0, 300);
      expect(leaves.map((l) => l.leafDigest)).toEqual(records.slice(0, 149).map((r) => r.digest));
      expect(await logs.getEvidenceLogPosition(records[150].id)).toBeNull();
      const attempt = appendNext(opened.adapter as StorageAdapter, 'default', 'after-the-hole');
      await expect(attempt).rejects.toBeInstanceOf(EvidenceLogRefusalError);
      await expect(attempt).rejects.toMatchObject({ reason: 'log_gap', chainId: 'default', sequenceNumber: 301 });
      // The other chain is unaffected.
      await appendNext(opened.adapter as StorageAdapter, 'tenant-b', 'tenant-b-goes-on');
    } finally {
      await opened.close();
    }
  });

  it('a record whose digest repeats an earlier position ends the backfilled prefix there', async () => {
    const { raw, close } = await backend.rawOnly();
    let records: Array<{ seq: number; digest: string; id: string }>;
    try {
      records = await recordsOf(raw, backend, 'tenant-b');
      // A malformed store: record 100 carries record 10's digest.
      if (backend.name === 'sqlite') {
        await raw.run('DROP TRIGGER envelopes_enforce_immutable');
        await raw.run(
          "UPDATE envelopes SET envelope = json_set(envelope, '$.integrity.canonicalDigest', ?) WHERE evidence_id = ?",
          [records[9].digest, records[99].id],
        );
      } else {
        await raw.run('BEGIN');
        await raw.run("SET LOCAL session_replication_role = 'replica'");
        await raw.run(
          "UPDATE envelopes SET envelope = jsonb_set(envelope, '{integrity,canonicalDigest}', to_jsonb(?::text)) WHERE evidence_id = ?",
          [records[9].digest, records[99].id],
        );
        await raw.run('COMMIT');
      }
    } finally {
      await close();
    }
    const opened = await backend.open();
    try {
      const tenant = (await logStoreFor(opened.adapter)!.getEvidenceLogCoverage()).find((c) => c.chainId === 'tenant-b')!;
      expect(tenant).toMatchObject({ size: 99, leafCount: 99, lastSequence: 200, missing: [{ from: 99, to: 199 }] });
    } finally {
      await opened.close();
    }
  });

  it('a chain that lost its tail before its log existed is refused new records, naming the chain', async () => {
    const { raw, close } = await backend.rawOnly();
    try {
      const records = await recordsOf(raw, backend, 'tenant-b');
      await deleteRecord(raw, backend, records[199].id);
    } finally {
      await close();
    }
    const opened = await backend.open();
    try {
      const logs = logStoreFor(opened.adapter)!;
      const tenant = (await logs.getEvidenceLogCoverage()).find((c) => c.chainId === 'tenant-b')!;
      expect(tenant).toMatchObject({ size: 199, lastSequence: 200, missing: [{ from: 199, to: 199 }] });
      const attempt = appendNext(opened.adapter as StorageAdapter, 'tenant-b', 'after-the-tail');
      await expect(attempt).rejects.toBeInstanceOf(EvidenceLogRefusalError);
      await expect(attempt).rejects.toMatchObject({ reason: 'log_gap', chainId: 'tenant-b', sequenceNumber: 201 });
      // The other chain is unaffected.
      await appendNext(opened.adapter as StorageAdapter, 'default', 'default-goes-on');
    } finally {
      await opened.close();
    }

    // Tzun.capture() on the refused chain reports the refusal as what it is.
    const target = backend.name === 'sqlite' ? { dbPath: backend.location() } : { dbUrl: backend.location() };
    const tzun = await Tzun.init({ mode: 'dev', ...target, chainId: 'tenant-b', verifyReads: false });
    try {
      const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { after: 'tail' }, action: 'approved', reason: 'r', aiSystemId: 'upgrade-suite' });
      expect(result.stored).toBe(false);
      expect(result.failure).toMatchObject({
        failureType: 'evidence_log_refused',
        diagnosticMetadata: {
          code: 'evidence_log_refused',
          refusalReason: 'log_gap',
          retryable: false,
          chainId: 'tenant-b',
          sequenceNumber: 201,
        },
      });
    } finally {
      await tzun.close();
    }
  });

  if (backend.name === 'postgres') {
    it('a store from another process during the backfill waits for it, then lands with its leaf', async () => {
      const url = backend.location();
      let release!: () => void;
      const gate = new Promise<void>((resolve) => { release = resolve; });
      let reached!: () => void;
      const backfilled = new Promise<void>((resolve) => { reached = resolve; });
      logMigrationTestHooks.afterBackfill = async () => {
        reached();
        await gate;
      };
      const migrating = new PostgresStorageAdapter(url);
      const migration = migrating.ensureTables();
      await backfilled;

      // A writer that does not run the migration (a process still on 0.5.0).
      const writer = new PostgresStorageAdapter(url);
      let landed = false;
      const write = appendNext(writer, 'default', 'during-the-backfill').then((env) => {
        landed = true;
        return env;
      });
      await new Promise((resolve) => setTimeout(resolve, 500));
      expect(landed).toBe(false);

      release();
      await migration;
      await write;
      expect(landed).toBe(true);
      try {
        expect(await migrating.logStore().getEvidenceLogPosition('during-the-backfill')).toMatchObject({
          leafIndex: RECORDS.default,
          source: 'capture',
        });
      } finally {
        await writer.close();
        await migrating.close();
      }
    });

    it('two processes opening the store at once migrate it once', async () => {
      const url = backend.location();
      const a = new PostgresStorageAdapter(url);
      const b = new PostgresStorageAdapter(url);
      try {
        await Promise.all([a.ensureTables(), b.ensureTables()]);
        const coverage = await a.logStore().getEvidenceLogCoverage();
        expect(coverage.map((c) => [c.chainId, c.leafCount, c.backfilled])).toEqual([
          ['default', 300, 300],
          ['tenant-b', 200, 200],
        ]);
        expect(await a.logStore().getStoreIdentity()).toEqual(await b.logStore().getStoreIdentity());
      } finally {
        await a.close();
        await b.close();
      }
    });
  }
});
