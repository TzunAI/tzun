/**
 * Evidence-log storage (Anchor §3, §4.3.2; Tree §5.2).
 *
 * The store's identity and origins, and the leaf every stored record gets in
 * its chain's evidence log — written by a trigger inside the storing
 * transaction on SQLite and Postgres, and in code on the memory adapter — on
 * each backend. The upgrade of a store that already has records is
 * `log-storage-upgrade.test.ts`; the anchoring tables are
 * `anchor-store.test.ts`.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import type { EvidenceEnvelope, StorageAdapter } from '@tzun/engine';
import { ChainConflictError } from '@tzun/engine';
import {
  DEFAULT_LOG_NAMESPACE,
  EvidenceLogRefusalError,
  InvalidLogNamespaceError,
  LogNamespaceMismatchError,
  LogStore,
  SqliteEncodingError,
  StoreIdentityMissingError,
  evidenceLogOrigin,
  logStoreFor,
} from '../../src/storage/log-store';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { Tzun } from '../../src/sdk/index';
import { LogBackend, OpenedStore, logBackends, refusal } from './helpers/log-store-backends';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

function envelope(evidenceId: string, sequenceNumber: number, overrides: { digest?: unknown } = {}): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'log-storage',
      aiOutput: { n: sequenceNumber },
      action: 'approved',
      reason: 'log storage',
      capturedAt: '2026-09-25T10:00:00.000Z',
      sequenceNumber,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: {
      canonicalDigest: (overrides.digest === undefined ? hex(evidenceId) : overrides.digest) as string,
      chainLink: null,
    },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

/** Arm the demo-tamper hooks through the one-shot bootstrap valve, quietly. */
async function armDemoHooks(adapter: StorageAdapter): Promise<void> {
  const spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  const saved = process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
  process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
  try {
    await (adapter as unknown as { armDemoTamperHooks(): Promise<void> }).armDemoTamperHooks();
  } finally {
    if (saved === undefined) delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
    else process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = saved;
    spy.mockRestore();
  }
}

// ── The rules every adapter applies to the evidence leaf ──────────────────

interface LeafCase {
  name: string;
  open(): Promise<{ adapter: StorageAdapter; logs: LogStore; close(): Promise<void> }>;
  dispose(): Promise<void>;
}

const sqlBackends = logBackends('log_storage');

const leafCases: LeafCase[] = [
  {
    name: 'memory',
    async open() {
      const adapter = new MemoryStorageAdapter();
      return { adapter, logs: adapter.logStore(), close: () => adapter.close() };
    },
    async dispose() {},
  },
  ...sqlBackends.map((backend): LeafCase => ({
    name: backend.name,
    async open() {
      await backend.fresh();
      const opened = await backend.open();
      return { adapter: opened.adapter as StorageAdapter, logs: logStoreFor(opened.adapter)!, close: () => opened.close() };
    },
    dispose: () => backend.dispose(),
  })),
];

describe.each(leafCases.map((c) => [c.name, c] as const))('the evidence leaf on %s (Tree §5.2)', (_name, backend) => {
  jest.setTimeout(60_000);
  let adapter: StorageAdapter;
  let logs: LogStore;
  let close: () => Promise<void>;

  beforeEach(async () => {
    ({ adapter, logs, close } = await backend.open());
  });
  afterEach(async () => close());
  afterAll(async () => backend.dispose());

  it('a stored record gets leaf sequenceNumber − 1 of its chain\'s log, with its digest', async () => {
    const { ns, storeId } = await logs.getStoreIdentity();
    await adapter.store(envelope('a-1', 1));
    await adapter.store(envelope('a-2', 2), 'default', {
      expectChainHead: { sequence: 1, digest: hex('a-1') },
    });
    const log = (await logs.getEvidenceLog('default'))!;
    expect(log.origin).toBe(evidenceLogOrigin(ns, storeId, 'default'));
    const leaves = await logs.listLogLeaves(log.logId, 0, 10);
    expect(leaves.map((l) => [l.leafIndex, l.leafDigest, l.sourceRef, l.source])).toEqual([
      [0, hex('a-1'), 'a-1', 'capture'],
      [1, hex('a-2'), 'a-2', 'capture'],
    ]);
    expect(await logs.getEvidenceLogPosition('a-2')).toMatchObject({
      origin: log.origin,
      chainId: 'default',
      leafIndex: 1,
      leafDigest: hex('a-2'),
      source: 'capture',
    });
    expect(await logs.getEvidenceLogPosition('unknown')).toBeNull();
    expect(await logs.getLogSize(log.logId)).toEqual({ size: 2, leafCount: 2 });
  });

  it('two chains have two logs, each counting from leaf 0', async () => {
    await adapter.store(envelope('d-1', 1));
    await adapter.store(envelope('t-1', 1), 'tenant-b');
    await adapter.store(envelope('d-2', 2));
    await adapter.store(envelope('t-2', 2), 'tenant-b');
    const logList = await logs.listLogs();
    expect(logList.map((l) => l.chainId)).toEqual(['default', 'tenant-b']);
    expect(new Set(logList.map((l) => l.origin)).size).toBe(2);
    expect((await logs.getEvidenceLogPosition('t-2'))!.leafIndex).toBe(1);
    expect((await logs.getEvidenceLogPosition('d-2'))!.leafIndex).toBe(1);
    const coverage = await logs.getEvidenceLogCoverage();
    expect(coverage.map((c) => [c.chainId, c.size, c.captured, c.backfilled, c.lastSequence, c.missing])).toEqual([
      ['default', 2, 2, 0, 2, []],
      ['tenant-b', 2, 2, 0, 2, []],
    ]);
  });

  it('a record with no predecessor leaf is refused, and nothing of it is written', async () => {
    await adapter.store(envelope('g-1', 1));
    const attempt = adapter.store(envelope('g-3', 3));
    await expect(attempt).rejects.toBeInstanceOf(EvidenceLogRefusalError);
    await expect(attempt).rejects.toMatchObject({ code: 'evidence_log_refused', reason: 'log_gap', chainId: 'default', sequenceNumber: 3 });
    expect(await adapter.retrieve('g-3')).toBeNull();
    expect(await adapter.getLastSequence()).toBe(1);
    expect(await logs.getEvidenceLogPosition('g-3')).toBeNull();

    // A chain's first record must be its first position; the log is not created either.
    await expect(adapter.store(envelope('n-2', 2), 'new-chain')).rejects.toMatchObject({ reason: 'log_gap' });
    expect(await logs.getEvidenceLog('new-chain')).toBeNull();
    expect(await adapter.getLastSequence('new-chain')).toBe(0);
  });

  it('a record that names no position is refused: a bad sequence number, a digest that is not a leaf, an empty chain id', async () => {
    await expect(adapter.store(envelope('s-0', 0))).rejects.toMatchObject({ reason: 'invalid_sequence_number' });
    await expect(adapter.store(envelope('s-f', 1.5))).rejects.toMatchObject({ reason: 'invalid_sequence_number' });
    await expect(adapter.store(envelope('d-p', 1, { digest: 'sha256:' + hex('x') }))).rejects.toMatchObject({ reason: 'invalid_digest' });
    await expect(adapter.store(envelope('d-u', 1, { digest: hex('x').toUpperCase() }))).rejects.toMatchObject({ reason: 'invalid_digest' });
    await expect(adapter.store(envelope('c-e', 1), '')).rejects.toMatchObject({ reason: 'empty_chain_id' });
    for (const id of ['s-0', 's-f', 'd-p', 'd-u', 'c-e']) expect(await adapter.retrieve(id)).toBeNull();
    expect(await logs.listLogs()).toEqual([]);
  });

  it('write once: a record at a position the log already has is refused as position_taken, and the leaf stays', async () => {
    await adapter.store(envelope('w-1', 1));
    await adapter.store(envelope('w-2', 2));
    // Another record at a position a record holds (a low-level store, no CAS).
    await expect(adapter.store(envelope('w-1b', 1))).rejects.toMatchObject({ reason: 'position_taken', sequenceNumber: 1 });
    // One that also repeats a digest the log has: the occupied position decides.
    await expect(adapter.store(envelope('w-1c', 1, { digest: hex('w-2') }))).rejects.toMatchObject({ reason: 'position_taken' });
    const log = (await logs.getEvidenceLog('default'))!;
    expect((await logs.listLogLeaves(log.logId, 0, 10)).map((l) => l.sourceRef)).toEqual(['w-1', 'w-2']);
    expect(await adapter.retrieve('w-1b')).toBeNull();
    expect(await logs.getEvidenceLogPosition('w-1b')).toBeNull();
    expect(await adapter.getLastSequence()).toBe(2);
    await adapter.store(envelope('w-3', 3));
    expect((await logs.getEvidenceLogPosition('w-3'))!.leafIndex).toBe(2);
  });

  it('a free position whose record id or digest is already a leaf is refused, and the chain goes on', async () => {
    await adapter.store(envelope('u-1', 1));
    await adapter.store(envelope('u-2', 2));
    // The next position, carrying a digest the log already has.
    const repeat = adapter.store(envelope('u-3', 3, { digest: hex('u-1') }));
    await expect(repeat).rejects.toBeInstanceOf(EvidenceLogRefusalError);
    await expect(repeat).rejects.toMatchObject({ reason: 'duplicate_leaf', chainId: 'default', sequenceNumber: 3 });
    expect(await adapter.retrieve('u-3')).toBeNull();
    expect(await adapter.getLastSequence()).toBe(2);
    // The chain's high-water mark did not move, so the next record lands.
    await adapter.store(envelope('u-3b', 3), 'default', { expectChainHead: { sequence: 2, digest: hex('u-2') } });
    expect((await logs.getEvidenceLogPosition('u-3b'))!.leafIndex).toBe(2);
  });

  it('a far position repeating a digest is refused as a gap, before the repeat, and does not move the high-water mark', async () => {
    for (let i = 1; i <= 3; i++) await adapter.store(envelope(`c-${i}`, i), 'c');
    // Refused and not stored. A stored far record would make its sequence the
    // chain's high-water mark, and every later in-order record of the chain
    // would then be refused with log_gap.
    await expect(adapter.store(envelope('c-far', 50, { digest: hex('c-1') }), 'c')).rejects.toMatchObject({ reason: 'log_gap' });
    expect(await adapter.retrieve('c-far')).toBeNull();
    expect(await adapter.getLastSequence('c')).toBe(3);
    await adapter.store(envelope('c-4', 4), 'c', { expectChainHead: { sequence: 3, digest: hex('c-3') } });
    expect((await logs.getEvidenceLogPosition('c-4'))!.leafIndex).toBe(3);
  });

  it('a record deleted and stored again at another position is refused: its id is already a leaf', async () => {
    await adapter.store(envelope('m-1', 1));
    await adapter.store(envelope('m-2', 2));
    await armDemoHooks(adapter);
    await adapter.deleteEnvelopeForDemo!('m-1');
    const moved = adapter.store(envelope('m-1', 3, { digest: hex('m-1 at 3') }));
    await expect(moved).rejects.toMatchObject({ reason: 'duplicate_leaf', sequenceNumber: 3 });
    expect(await adapter.retrieve('m-1')).toBeNull();
    expect(await adapter.getLastSequence()).toBe(2);
  });

  it('a chain id that names no log is refused before anything is written: a lone surrogate, U+0000, not a string', async () => {
    for (const chainId of ['bad\uD800', '\uDC00', 'a\u0000b', 42 as unknown as string]) {
      const attempt = adapter.store(envelope('x-1', 1), chainId);
      await expect(attempt).rejects.toBeInstanceOf(EvidenceLogRefusalError);
      await expect(attempt).rejects.toMatchObject({ code: 'evidence_log_refused', reason: 'invalid_chain_id', retryable: false });
      await expect(
        adapter.storeIdempotent!(envelope('x-1', 1), chainId, { idempotency: { key: 'kx', fingerprint: 'f' } }),
      ).rejects.toMatchObject({ reason: 'invalid_chain_id' });
    }
    expect(await adapter.retrieve('x-1')).toBeNull();
    expect(await logs.listLogs()).toEqual([]);
  });

  it('the demo\'s tamper — delete a record, store a rewritten copy under its id — keeps the original leaf', async () => {
    await adapter.store(envelope('rw-1', 1));
    await adapter.store(envelope('rw-2', 2));
    await armDemoHooks(adapter);
    const original = (await adapter.retrieve('rw-1'))!;
    await adapter.deleteEnvelopeForDemo!('rw-1');
    const rewritten = { ...original, payload: { ...original.payload, reason: 'retroactively edited' } };
    rewritten.integrity = { ...original.integrity, canonicalDigest: hex('the rewritten record') };
    await adapter.store(rewritten);

    expect((await adapter.retrieve('rw-1'))!.integrity.canonicalDigest).toBe(hex('the rewritten record'));
    const position = (await logs.getEvidenceLogPosition('rw-1'))!;
    expect(position).toMatchObject({ leafIndex: 0, leafDigest: hex('rw-1'), source: 'capture' });
    // The chain goes on; its log is unchanged by the tamper.
    await adapter.store(envelope('rw-3', 3));
    expect((await logs.getLogSize(position.logId))).toEqual({ size: 3, leafCount: 3 });
  });

  it('a refused compare-and-swap writes no leaf', async () => {
    await adapter.store(envelope('c-1', 1), 'default', { expectChainHead: { sequence: 0, digest: null } });
    await expect(
      adapter.store(envelope('c-2', 2), 'default', { expectChainHead: { sequence: 0, digest: null } }),
    ).rejects.toBeInstanceOf(ChainConflictError);
    const log = (await logs.getEvidenceLog('default'))!;
    expect(await logs.getLogSize(log.logId)).toEqual({ size: 1, leafCount: 1 });
  });

  it('storeIdempotent writes the leaf with the record, and a replay writes none', async () => {
    const claim = { idempotency: { key: 'k-1', fingerprint: 'fp-1' } };
    await adapter.storeIdempotent!(envelope('i-1', 1), undefined, claim);
    await adapter.storeIdempotent!(envelope('i-1-retry', 2), undefined, claim);
    const log = (await logs.getEvidenceLog('default'))!;
    expect((await logs.listLogLeaves(log.logId, 0, 10)).map((l) => l.sourceRef)).toEqual(['i-1']);
    await expect(adapter.storeIdempotent!(envelope('i-3', 3), undefined, { idempotency: { key: 'k-3', fingerprint: 'fp' } }))
      .rejects.toMatchObject({ reason: 'log_gap' });
  });
});

// ── The database guards (SQLite and Postgres) ─────────────────────────────

describe.each(sqlBackends.map((b) => [b.name, b] as const))('the log tables on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(60_000);
  let store: OpenedStore<unknown>;
  let adapter: StorageAdapter;
  let logs: LogStore;

  beforeEach(async () => {
    await backend.fresh();
    store = await backend.open();
    adapter = store.adapter as StorageAdapter;
    logs = logStoreFor(store.adapter)!;
    await adapter.store(envelope('g-1', 1));
    await adapter.store(envelope('g-2', 2));
  });
  afterEach(async () => store.close());
  afterAll(async () => backend.dispose());

  it('store_identity, logs and log_leaves refuse UPDATE and DELETE (and TRUNCATE)', async () => {
    const { raw } = store;
    await refusal(raw.run('UPDATE store_identity SET ns = ?', ['test.stolen']), /immutable/);
    await refusal(raw.run('DELETE FROM store_identity'), /immutable/);
    await refusal(raw.run('UPDATE logs SET origin = ?', ['elsewhere']), /insert-only/);
    await refusal(raw.run('DELETE FROM logs'), /insert-only/);
    await refusal(raw.run('UPDATE log_leaves SET leaf_digest = ? WHERE leaf_index = 0', [hex('forged')]), /insert-only/);
    await refusal(raw.run('DELETE FROM log_leaves WHERE leaf_index = 1'), /insert-only/);
    if (backend.name === 'postgres') {
      for (const table of ['store_identity', 'logs', 'log_leaves']) {
        await refusal(raw.run(`TRUNCATE ${table} CASCADE`), /refused/);
      }
    }
    const log = (await logs.getEvidenceLog('default'))!;
    expect((await logs.listLogLeaves(log.logId, 0, 10)).map((l) => l.leafDigest)).toEqual([hex('g-1'), hex('g-2')]);
  });

  it('a raw insert cannot place a leaf out of order, twice, or under an origin the identity does not name', async () => {
    const { raw } = store;
    const log = (await logs.getEvidenceLog('default'))!;
    const at = '2026-09-25T10:00:00Z';
    await refusal(raw.run(
      "INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, ?, ?, ?, 'capture', ?)",
      [log.logId, 5, hex('late'), 'late', at],
    ), /log_gap/);
    await refusal(raw.run(
      "INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, ?, ?, ?, 'capture', ?)",
      [log.logId, 1, hex('replacement'), 'replacement', at],
    ));
    await refusal(raw.run(
      "INSERT INTO logs (origin, kind, chain_id, created_at) VALUES (?, 'evidence', ?, ?)",
      [`${DEFAULT_LOG_NAMESPACE}/${'0'.repeat(32)}/evidence/6f74686572`, 'other', at],
    ), /origin/);
    if (backend.name === 'sqlite') {
      // REPLACE resolves a conflict by deleting the row without firing a
      // DELETE trigger; the leaf is refused before that can happen.
      await refusal(raw.run(
        "INSERT OR REPLACE INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, ?, ?, ?, 'capture', ?)",
        [log.logId, 0, hex('replaced'), 'g-1', at],
      ), /written once/);
    }
    expect((await logs.listLogLeaves(log.logId, 0, 10)).map((l) => l.sourceRef)).toEqual(['g-1', 'g-2']);
  });

  it('a transaction that stores a record and rolls back leaves no leaf behind', async () => {
    const { raw } = store;
    // A later statement of the storing transaction fails after the record and
    // its leaf are written: the capture revision is refused for one id.
    if (backend.name === 'sqlite') {
      await raw.run(`CREATE TRIGGER fail_one_revision BEFORE INSERT ON envelope_revisions
                     WHEN NEW.evidence_id = 'doomed' BEGIN SELECT RAISE(ABORT, 'injected failure'); END`);
    } else {
      await raw.run(`CREATE FUNCTION fail_one_revision() RETURNS TRIGGER AS $$
                     BEGIN IF NEW.evidence_id = 'doomed' THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END;
                     $$ LANGUAGE plpgsql`);
      await raw.run(`CREATE TRIGGER fail_one_revision BEFORE INSERT ON envelope_revisions
                     FOR EACH ROW EXECUTE FUNCTION fail_one_revision()`);
    }
    await refusal(adapter.store(envelope('doomed', 3)), /injected failure/);
    expect(await adapter.retrieve('doomed')).toBeNull();
    expect(await logs.getEvidenceLogPosition('doomed')).toBeNull();
    // The position is still free for the record that does commit.
    await adapter.store(envelope('g-3', 3));
    expect((await logs.getEvidenceLogPosition('g-3'))!.leafIndex).toBe(2);
  });

  it('a writer that is not the SDK populates the leaf too', async () => {
    // A second connection with none of the adapter's registered SQL functions.
    const other = await backend.rawOnly();
    try {
      const env = envelope('raw-3', 3);
      await other.raw.run(
        backend.name === 'sqlite'
          ? 'INSERT INTO envelopes (evidence_id, envelope, captured_at, captured_at_ms, ai_system_id, digest, chain_id) VALUES (?, ?, ?, 0, ?, ?, ?)'
          : 'INSERT INTO envelopes (evidence_id, envelope, captured_at, ai_system_id, digest, chain_id) VALUES (?, ?::jsonb, ?, ?, ?, ?)',
        [env.payload.evidenceId, JSON.stringify(env), env.payload.capturedAt, env.payload.aiSystemId, env.integrity.canonicalDigest, 'default'],
      );
    } finally {
      await other.close();
    }
    expect(await logs.getEvidenceLogPosition('raw-3')).toMatchObject({ leafIndex: 2, source: 'capture', leafDigest: hex('raw-3') });
  });
});

// ── The store identity (Anchor §4.3.2) ───────────────────────────────────────

describe.each(sqlBackends.map((b) => [b.name, b] as const))('the store identity on %s (Anchor §4.3.2)', (_name, backend: LogBackend) => {
  jest.setTimeout(60_000);
  afterAll(async () => backend.dispose());

  it('is minted once, under local.invalid by default, and survives reopening', async () => {
    await backend.fresh();
    const first = await backend.open();
    const identity = await logStoreFor(first.adapter)!.getStoreIdentity();
    expect(identity.ns).toBe(DEFAULT_LOG_NAMESPACE);
    expect(identity.storeId).toMatch(/^[0-9a-f]{32}$/);
    await first.close();
    const again = await backend.open();
    expect(await logStoreFor(again.adapter)!.getStoreIdentity()).toEqual(identity);
    await again.close();
  });

  it('takes a configured namespace when minted, refuses a different one later, and accepts the same one or none', async () => {
    await backend.fresh();
    const first = await backend.open({ logNamespace: 'test.tzun.ai' });
    const identity = await logStoreFor(first.adapter)!.getStoreIdentity();
    expect(identity.ns).toBe('test.tzun.ai');
    await (first.adapter as StorageAdapter).store(envelope('ns-1', 1));
    const origin = (await logStoreFor(first.adapter)!.getEvidenceLog('default'))!.origin;
    expect(origin).toBe(`test.tzun.ai/${identity.storeId}/evidence/64656661756c74`);
    await first.close();

    await expect(backend.open({ logNamespace: 'log.tzun.ai' })).rejects.toBeInstanceOf(LogNamespaceMismatchError);
    await expect(backend.open({ logNamespace: 'log.tzun.ai' })).rejects.toMatchObject({
      code: 'log_namespace_mismatch',
      stored: 'test.tzun.ai',
      configured: 'log.tzun.ai',
    });
    for (const options of [{ logNamespace: 'test.tzun.ai' }, {}]) {
      const reopened = await backend.open(options);
      expect(await logStoreFor(reopened.adapter)!.getStoreIdentity()).toEqual(identity);
      await reopened.close();
    }
  });

  it('refuses a namespace the origin rules cannot take', async () => {
    await backend.fresh();
    for (const logNamespace of ['has space', 'a+b', '', 'test.tzun.ai/demo', 'Example.COM', 'a!b', 'a..b', '-a.b']) {
      await expect(backend.open({ logNamespace })).rejects.toBeInstanceOf(InvalidLogNamespaceError);
    }
  });

  it('a wiped store is a new store: a new identity, new origins', async () => {
    await backend.fresh();
    const first = await backend.open();
    await (first.adapter as StorageAdapter).store(envelope('w-1', 1));
    const before = (await logStoreFor(first.adapter)!.getEvidenceLog('default'))!.origin;
    await first.close();

    await backend.fresh();
    const wiped = await backend.open();
    await (wiped.adapter as StorageAdapter).store(envelope('w-1', 1));
    const after = (await logStoreFor(wiped.adapter)!.getEvidenceLog('default'))!.origin;
    await wiped.close();
    expect(after).not.toBe(before);
    expect(after.endsWith('/evidence/64656661756c74')).toBe(true);
  });

  it('a store whose identity was removed while its logs remain is refused', async () => {
    await backend.fresh();
    const first = await backend.open();
    await (first.adapter as StorageAdapter).store(envelope('m-1', 1));
    // Step around the guard explicitly, as only a table owner can.
    if (backend.name === 'sqlite') {
      await first.raw.run('DROP TRIGGER store_identity_block_delete');
      await first.raw.run('DELETE FROM store_identity');
    } else {
      await first.raw.run('BEGIN');
      await first.raw.run("SET LOCAL session_replication_role = 'replica'");
      await first.raw.run('DELETE FROM store_identity');
      await first.raw.run('COMMIT');
    }
    // The running adapter can no longer name a new chain's log.
    await expect((first.adapter as StorageAdapter).store(envelope('m-x', 1), 'another'))
      .rejects.toMatchObject({ reason: 'store_identity_missing' });
    await first.close();
    await expect(backend.open()).rejects.toBeInstanceOf(StoreIdentityMissingError);
  });
});

describe('opening a SQLite store that is already migrated', () => {
  let dir: string;
  let file: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-reopen-'));
    file = join(dir, 'store.db');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('writes nothing to its schema, so another process on the file sees no schema change', async () => {
    const first = new SqliteStorageAdapter(file);
    await first.store(envelope('r-1', 1));
    await first.close();
    const probe = new Database(file);
    const before = probe.pragma('schema_version', { simple: true });
    const reopened = new SqliteStorageAdapter(file);
    expect(probe.pragma('schema_version', { simple: true })).toBe(before);
    await reopened.store(envelope('r-2', 2));
    await reopened.close();
    probe.close();
  });

  it('replaces a log trigger whose statement is not the current one', async () => {
    const first = new SqliteStorageAdapter(file);
    await first.close();
    const db = new Database(file);
    db.exec('DROP TRIGGER log_leaves_block_delete');
    db.exec("CREATE TRIGGER log_leaves_block_delete BEFORE DELETE ON log_leaves BEGIN SELECT 1; END");
    db.close();
    const reopened = new SqliteStorageAdapter(file);
    await reopened.store(envelope('t-1', 1));
    const raw = (reopened as unknown as { db: import('better-sqlite3').Database }).db;
    expect(await refusal(async () => raw.prepare('DELETE FROM log_leaves').run())).toMatch(/insert-only/);
    await reopened.close();
  });
});

describe('the store identity: SQLite encoding and the memory adapter', () => {
  it('a SQLite store that is not UTF-8 is refused before anything is written to it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tzun-test-utf16-'));
    try {
      const file = join(dir, 'utf16.db');
      const db = new Database(file);
      db.pragma("encoding = 'UTF-16le'");
      db.exec('CREATE TABLE marker (x TEXT)');
      db.close();
      expect(() => new SqliteStorageAdapter(file)).toThrow(SqliteEncodingError);
      const check = new Database(file);
      try {
        const tables = check.prepare("SELECT name FROM sqlite_schema WHERE type = 'table'").all();
        expect(tables).toEqual([{ name: 'marker' }]);
      } finally {
        check.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('every memory adapter is a new store, with the namespace it was given', async () => {
    const a = new MemoryStorageAdapter();
    const b = new MemoryStorageAdapter({ logNamespace: 'test.memory' });
    const ia = await a.logStore().getStoreIdentity();
    const ib = await b.logStore().getStoreIdentity();
    expect(ia.ns).toBe(DEFAULT_LOG_NAMESPACE);
    expect(ib.ns).toBe('test.memory');
    expect(ia.storeId).not.toBe(ib.storeId);
    expect(() => new MemoryStorageAdapter({ logNamespace: 'no spaces allowed' })).toThrow(InvalidLogNamespaceError);
  });
});

// ── Through the SDK ───────────────────────────────────────────────────────

describe('Tzun.capture() on a SQLite store', () => {
  it('each capture is at leaf sequenceNumber − 1 of its chain\'s log', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tzun-test-capture-logs-'));
    try {
      const file = join(dir, 'capture.db');
      const tzun = await Tzun.init({ mode: 'dev', dbPath: file });
      const results = [];
      for (let i = 0; i < 3; i++) {
        results.push(await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: 'ok', aiSystemId: 'sys' }));
      }
      await tzun.close();
      const reader = new SqliteStorageAdapter(file);
      try {
        for (const r of results) {
          const position = await reader.logStore().getEvidenceLogPosition(r.envelope.payload.evidenceId);
          expect(position).toMatchObject({
            chainId: 'default',
            leafIndex: r.envelope.payload.sequenceNumber - 1,
            leafDigest: r.envelope.integrity.canonicalDigest,
            source: 'capture',
          });
        }
      } finally {
        await reader.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
