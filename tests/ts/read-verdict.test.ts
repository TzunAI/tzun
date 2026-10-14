/**
 * Every local read carries an integrity verdict, and no verdict ever
 * withholds a record.
 *
 * `tzun.get(id)` and `tzun.list()` return `{ envelope, verdict }`. The verdict
 * is computed by the verifying storage proxy, which is on by default for every
 * local adapter and switched off by one option, `verifyReads: false`. A read
 * of a tampered record returns the tampered record with an `invalid` verdict
 * beside it: blocking the read would break `recovery.annotate()` on exactly
 * the records that need it, and a single UPDATE could deny reads of a range.
 *
 * Legs: memory and sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own,
 * emptied before each case.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { TamperIncident, TzunConfig } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { VerifyingStorageProxy } from '../../src/monitoring/storage-proxy';
import { rewriteStoredEnvelope } from './helpers/tamper-store';

// A schema of this file's own, emptied before each Postgres case.
const pgSchema = pgSuiteSchema('read_verdict');

interface Leg {
  name: 'memory' | 'sqlite' | 'postgres';
  /** Storage config for Tzun.init(), on a store with nothing in it. */
  config: () => Promise<{ config: TzunConfig; teardown: () => Promise<void> }>;
}

const legs: Leg[] = [
  { name: 'memory', config: async () => ({ config: {}, teardown: async () => undefined }) },
  {
    name: 'sqlite',
    config: async () => {
      const dbPath = path.join(os.tmpdir(), `tzun-test-read-verdict-${process.pid}-${Math.random().toString(36).slice(2)}.db`);
      return {
        config: { dbPath },
        teardown: async () => {
          for (const suffix of ['', '-wal', '-shm']) {
            try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
          }
        },
      };
    },
  },
];
if (PG_TESTS_ENABLED) {
  legs.push({
    name: 'postgres',
    config: async () => {
      await pgSchema.empty();
      return { config: { dbUrl: pgSchema.url }, teardown: async () => undefined };
    },
  });
}

async function captureThree(tzun: Tzun): Promise<string[]> {
  const ids: string[] = [];
  for (let i = 1; i <= 3; i++) {
    const r = await tzun.capture({
      aiOutput: { step: i },
      action: 'approved',
      reason: `step ${i}`,
      decider: { kind: 'human' as const, id: 'acct:reviewer-acme.com', agent: null, credential: null, freshness: null },
    });
    expect(r.stored).toBe(true);
    ids.push(r.envelope.payload.evidenceId);
  }
  return ids;
}

async function annotate(tzun: Tzun, evidenceId: string, incidentId = 'inc-read-verdict'): Promise<void> {
  const incident: TamperIncident = {
    id: incidentId,
    detectedAt: new Date().toISOString(),
    severity: 'warning',
    type: 'digest_mismatch',
    affectedRecords: [evidenceId],
    details: 'reviewed in the read-verdict suite',
    status: 'open',
  };
  await tzun.getStorage().storeIncident(incident);
  await tzun.recovery.annotate(incidentId, { authorizedBy: 'auditor@acme.example', notes: 'looked at it' });
}

describe.each(legs)('reads carry a verdict — $name', (leg) => {
  let tzun: Tzun;
  let teardown: () => Promise<void>;

  async function init(extra: TzunConfig = {}): Promise<Tzun> {
    const made = await leg.config();
    teardown = made.teardown;
    tzun = await Tzun.init({ ...made.config, ...extra });
    return tzun;
  }

  afterEach(async () => {
    await tzun?.close();
    await teardown?.();
  });

  it('get() returns the envelope and a valid verdict for an untouched record', async () => {
    await init();
    const [, id] = await captureThree(tzun);

    const read = await tzun.get(id);
    expect(read).not.toBeNull();
    expect(read!.envelope.payload.evidenceId).toBe(id);
    const { verdict } = read!;
    expect(verdict.status).toBe('valid');
    expect(verdict.digest.status).toBe('valid');
    expect(verdict.digest.recomputed).toBe(read!.envelope.integrity.canonicalDigest);
    expect(verdict.digest.stored).toBe(read!.envelope.integrity.canonicalDigest);
    expect(verdict.custodyTrail).toMatchObject({ status: 'unmeasured', reason: 'nothing_to_measure' });
    expect(verdict.custodyTrail.ledger).toMatchObject({ valid: true, rows: 0, hashedEntries: 0 });
    expect(verdict.chainLink).toEqual({
      status: 'unmeasured',
      reason: 'not_checked_on_read',
      predecessorDigest: null,
    });
    expect(Number.isNaN(Date.parse(verdict.checkedAt))).toBe(false);
  });

  it('get() of an id the store does not hold is null', async () => {
    await init();
    expect(await tzun.get('00000000-0000-4000-8000-000000000000')).toBeNull();
  });

  it('a rewritten payload is returned, not withheld, with an invalid verdict naming both digests', async () => {
    await init();
    const ids = await captureThree(tzun);
    const original = (await tzun.get(ids[1]))!.envelope;
    await rewriteStoredEnvelope(tzun.getStorage(), ids[1], (e) => {
      e.payload.reason = 'rewritten after the fact';
    });

    const read = await tzun.get(ids[1]);
    expect(read!.envelope.payload.reason).toBe('rewritten after the fact');
    expect(read!.verdict.status).toBe('invalid');
    expect(read!.verdict.digest.status).toBe('invalid');
    expect(read!.verdict.digest.reason).toBe('digest_mismatch');
    expect(read!.verdict.digest.stored).toBe(original.integrity.canonicalDigest);
    expect(read!.verdict.digest.recomputed).toMatch(/^[0-9a-f]{64}$/);
    expect(read!.verdict.digest.recomputed).not.toBe(original.integrity.canonicalDigest);

    const listed = await tzun.list({ order: 'asc' });
    expect(listed.map((r) => r.envelope.payload.evidenceId)).toEqual(ids);
    expect(listed.map((r) => r.verdict.status)).toEqual(['valid', 'invalid', 'valid']);
  });

  it('a repaired record reads with a valid custody trail backed by its ledger row', async () => {
    await init();
    const ids = await captureThree(tzun);
    await annotate(tzun, ids[0]);

    const { verdict, envelope } = (await tzun.get(ids[0]))!;
    expect(envelope.custodyChain.map((e) => e.action)).toEqual(['decision_captured', 'reviewed']);
    expect(verdict.status).toBe('valid');
    expect(verdict.custodyTrail.status).toBe('valid');
    expect(verdict.custodyTrail.reason).toBeUndefined();
    expect(verdict.custodyTrail.ledger).toMatchObject({ valid: true, rows: 1, hashedEntries: 1, unhashedEntries: 1 });
  });

  it('a hashed custody entry deleted from the end of the mirror reads invalid, and annotate still works on it', async () => {
    await init();
    const ids = await captureThree(tzun);
    await annotate(tzun, ids[0], 'inc-1');
    await rewriteStoredEnvelope(tzun.getStorage(), ids[0], (e) => {
      e.custodyChain.pop();
    });

    const { verdict } = (await tzun.get(ids[0]))!;
    expect(verdict.status).toBe('invalid');
    expect(verdict.digest.status).toBe('valid');
    expect(verdict.custodyTrail).toMatchObject({ status: 'invalid', reason: 'mirror_entry_missing' });

    // The read did not block the recovery path that reads the same record.
    await annotate(tzun, ids[0], 'inc-2');
    expect((await tzun.getStorage().getIncident('inc-2'))!.status).toBe('acknowledged');
  });

  it('a custody ledger that cannot be read leaves the record readable, with the error in the verdict', async () => {
    await init();
    const [id] = await captureThree(tzun);
    const adapter = tzun.getStorage();
    adapter.listCustodyEntries = async () => {
      throw new Error('custody_entries is unreadable');
    };

    const read = await tzun.get(id);
    expect(read!.envelope.payload.evidenceId).toBe(id);
    expect(read!.verdict.status).toBe('valid');
    expect(read!.verdict.custodyTrail).toEqual({
      status: 'unmeasured',
      reason: 'custody_ledger_unreadable',
      ledger: null,
      detail: 'custody_entries is unreadable',
    });
    const listed = await tzun.list();
    expect(listed).toHaveLength(3);
    expect(listed.every((r) => r.verdict.custodyTrail.reason === 'custody_ledger_unreadable')).toBe(true);
  });

  it('the proxy is on without monitoring, and getStorage() is still the configured adapter', async () => {
    await init();
    const internal = (tzun as unknown as { storage: unknown }).storage;
    expect(internal).toBeInstanceOf(VerifyingStorageProxy);
    const expected = { memory: MemoryStorageAdapter, sqlite: SqliteStorageAdapter, postgres: PostgresStorageAdapter }[leg.name];
    expect(tzun.getStorage()).toBeInstanceOf(expected);
  });

  it('verifyReads: false is the one switch: no proxy, and every read says unmeasured instead of passing', async () => {
    await init({ verifyReads: false });
    const ids = await captureThree(tzun);
    expect((tzun as unknown as { storage: unknown }).storage).not.toBeInstanceOf(VerifyingStorageProxy);
    await rewriteStoredEnvelope(tzun.getStorage(), ids[2], (e) => {
      e.payload.reason = 'rewritten';
    });

    const read = await tzun.get(ids[2]);
    expect(read!.envelope.payload.reason).toBe('rewritten');
    expect(read!.verdict.status).toBe('unmeasured');
    expect(read!.verdict.digest).toMatchObject({ status: 'unmeasured', reason: 'read_verification_off', recomputed: '' });
    expect(read!.verdict.custodyTrail).toMatchObject({ status: 'unmeasured', reason: 'read_verification_off' });
    expect((await tzun.list()).every((r) => r.verdict.status === 'unmeasured')).toBe(true);
  });

  it('with monitoring on, a tampered read is also reported on the bus as a tamper incident', async () => {
    await init({ monitoring: { enabled: true } });
    const ids = await captureThree(tzun);
    const incidents: TamperIncident[] = [];
    tzun.on('tamper', (incident) => incidents.push(incident));
    await rewriteStoredEnvelope(tzun.getStorage(), ids[0], (e) => {
      e.payload.action = 'rejected';
    });

    await tzun.get(ids[0]);
    await (tzun as unknown as { tamperDetector: { settle(): Promise<void> } }).tamperDetector.settle();
    expect(incidents.map((i) => i.type)).toEqual(['digest_mismatch']);
    expect(incidents[0].affectedRecords).toEqual([ids[0]]);
  });

  if (leg.name !== 'memory') {
    it('the credential store behind a SQL adapter is still reachable through the proxy', async () => {
      await init();
      expect(tzun.getCredentialStore()).toBeDefined();
    });
  }
});

describe('verifyReads on the cloud transport', () => {
  const fetchFn = async () => new Response('{}', { status: 200 });

  it('is off by default: the transport has no read path, so there is nothing to wrap', async () => {
    const tzun = await Tzun.init({ apiKey: 'tzk_test', _httpFetchFn: fetchFn });
    try {
      expect((tzun as unknown as { storage: unknown }).storage).not.toBeInstanceOf(VerifyingStorageProxy);
    } finally {
      await tzun.close();
    }
  });
});
