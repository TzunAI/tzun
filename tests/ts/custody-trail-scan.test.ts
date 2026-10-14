import { testEvidenceId } from './helpers/evidence-id';
/**
 * The scanner raises `custody_trail_invalid`.
 *
 * `custodyChain` sits outside the v1.0 hashed field set, so an insider who
 * rewrites, reorders or deletes a custody entry — the record of who relinked,
 * forked or reviewed a record — changes no digest and breaks no chain link.
 * `verifyEnvelope()` reports it (`custodyTrailValid`) and an export check can
 * see it, but without an incident a scheduled scan would stay silent about
 * it, while the platform reports it in chain-status.
 *
 * So, per record, Phase 1 checks the trail from the envelope
 * (`verifyCustodyTrail`) and against the store's `custody_entries` ledger
 * (`verifyCustodyLedger`) — the ledger row is what remembers an entry deleted
 * from the END of the trail, which the envelope alone cannot show — and checks
 * every 'relinked' entry's `relinkDigest` against the relink record it names.
 * A failure is one critical `custody_trail_invalid` incident per record, with
 * its own dedupe key. `verifyChainCompleteness()` reports the same records in
 * `custodyTrailInvalid`, outside `valid`.
 *
 * ADAPTERS. Memory and SQLite always; Postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of its own per case,
 * dropped after it.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  CustodyEntry,
  EvidenceEnvelope,
  MonitoringEvent,
  RelinkRecord,
  ScanCompletedEvent,
  ScannerConfig,
  SchemaRegistry,
  StorageAdapter,
  TamperIncident,
  assembleEnvelope,
  verifyChainCompleteness,
} from '@tzun/engine';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { ScheduledScanner } from '../../src/monitoring/scheduled-scanner';
import { TamperDetector } from '../../src/monitoring/tamper-detector';
import { computeRelinkDigest } from '../../src/monitoring/recovery-manager';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { PG_TESTS_ENABLED, pgCaseSchema } from './helpers/postgres-test-db';

const registry = new SchemaRegistry();

const scannerConfig: ScannerConfig = {
  batchSize: 100,
  workers: 2,
  mode: 'interval',
  intervalMs: 0,
  verifyAttestation: false,
  verifyChainCompleteness: true,
};

interface Opened {
  storage: StorageAdapter;
  close: () => Promise<void>;
}

const legs: Array<{ name: string; open: () => Promise<Opened> }> = [
  {
    name: 'memory',
    open: async () => {
      const storage = new MemoryStorageAdapter();
      return { storage, close: async () => storage.close() };
    },
  },
  {
    name: 'sqlite',
    open: async () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-'));
      const storage = new SqliteStorageAdapter(path.join(dir, 'custody.db'));
      return {
        storage,
        close: async () => {
          await storage.close();
          fs.rmSync(dir, { recursive: true, force: true });
        },
      };
    },
  },
];

if (PG_TESTS_ENABLED) {
  legs.push({
    name: 'postgres',
    open: async () => {
      const schema = await pgCaseSchema('custody_trail_scan');
      const storage = new PostgresStorageAdapter(schema.url);
      await storage.ensureTables();
      return {
        storage,
        close: async () => {
          await storage.close();
          await schema.drop();
        },
      };
    },
  });
}

/** Append `n` correctly linked records, `ev-1`..`ev-n`. */
async function appendChain(storage: StorageAdapter, n: number): Promise<EvidenceEnvelope[]> {
  const out: EvidenceEnvelope[] = [];
  let previousDigest: string | undefined;
  for (let i = 1; i <= n; i++) {
    const envelope = assembleEnvelope({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 'sys-custody-scan', aiOutput: { r: i }, action: 'approved', reason: `reason ${i}` }, { previousDigest: previousDigest, sequenceNumber: i, signoffExpectation: null, evidenceId: testEvidenceId(`ev-${i}`) });
    await storage.store(envelope);
    previousDigest = envelope.integrity.canonicalDigest;
    out.push(envelope);
  }
  return out;
}

const reviewed = (actor = 'op@example.com'): CustodyEntry => ({
  timestamp: '2026-09-19T10:00:00.000Z',
  actor,
  action: 'reviewed',
  systemId: 'tzun-recovery',
  metadata: { incidentId: 'inc-custody-scan', recoveryTier: 'annotation' },
});

/** Append a hashed custody entry to `evidenceId` and return its custodyChain index. */
async function appendHashed(storage: StorageAdapter, evidenceId: string, entry: CustodyEntry): Promise<number> {
  await storage.appendCustodyEntry(evidenceId, entry);
  const stored = await storage.retrieve(evidenceId);
  return stored!.custodyChain.length - 1;
}

type CustodyEvent = Extract<MonitoringEvent, { type: 'custody_trail_invalid' }>;

describe.each(legs)('the scanner raises custody_trail_invalid — $name adapter', (leg) => {
  let opened: Opened;
  let storage: StorageAdapter;
  let detector: TamperDetector;
  let scanner: ScheduledScanner;
  let events: MonitoringEvent[];

  beforeEach(async () => {
    opened = await leg.open();
    storage = opened.storage;
    const bus = new MonitoringEventBus();
    events = [];
    bus.subscribe((e) => events.push(e));
    detector = new TamperDetector(bus, storage);
    scanner = new ScheduledScanner(storage, bus, registry, scannerConfig);
  });
  afterEach(async () => {
    await detector.settle();
    await opened.close();
  });

  /** One pass; returns the custody events and scan_completed of that pass only. */
  const pass = async (): Promise<{ custody: CustodyEvent[]; completed: ScanCompletedEvent }> => {
    const from = events.length;
    await scanner.runFullPass();
    await detector.settle();
    const mine = events.slice(from);
    const completed = mine.find((e): e is ScanCompletedEvent => e.type === 'scan_completed')!;
    return { custody: mine.filter((e): e is CustodyEvent => e.type === 'custody_trail_invalid'), completed };
  };

  const walk = async () =>
    verifyChainCompleteness(storage, registry, {
      fromSequence: 1,
      toSequence: await storage.getLastSequence(),
      chainId: await storage.getActiveChainId(),
    });

  const incidents = async (): Promise<TamperIncident[]> => storage.listIncidents();

  it('an untouched custody trail raises nothing', async () => {
    await appendChain(storage, 3);
    await appendHashed(storage, testEvidenceId('ev-2'), reviewed());
    await appendHashed(storage, testEvidenceId('ev-2'), reviewed('second@example.com'));

    const { custody, completed } = await pass();

    expect(custody).toEqual([]);
    expect(completed.custodyTrailInvalid).toBe(0);
    expect((await walk()).custodyTrailInvalid).toEqual([]);
  });

  it("a mirrored entry's actor rewritten: exactly one custody_trail_invalid naming the record and the index", async () => {
    await appendChain(storage, 3);
    const index = await appendHashed(storage, testEvidenceId('ev-2'), reviewed());
    await rewriteStoredEnvelope(storage, testEvidenceId('ev-2'), (e) => {
      (e.custodyChain[index] as { actor: string }).actor = 'someone-else@example.com';
    });

    const { custody, completed } = await pass();

    expect(custody).toHaveLength(1);
    expect(custody[0].evidenceId).toBe(testEvidenceId('ev-2'));
    // What the envelope shows (the entry no longer recomputes) and what the
    // ledger shows (the entry disagrees with its row) — both at that index.
    expect(custody[0].failures.map((f) => f.reason).sort()).toEqual(['entry_hash_mismatch', 'mirror_fields_mismatch']);
    expect(custody[0].failures.every((f) => f.index === index)).toBe(true);
    expect(completed.custodyTrailInvalid).toBe(1);
    expect(completed.issuesFound).toBe(1);

    const raised = (await incidents()).filter((i) => i.type === 'custody_trail_invalid');
    expect(raised.map((i) => [i.severity, i.affectedRecords])).toEqual([['critical', [testEvidenceId('ev-2')]]]);

    // Reported by the walk too, and — deliberately, for now — outside `valid`.
    const result = await walk();
    expect(result.custodyTrailInvalid).toEqual([testEvidenceId('ev-2')]);
    expect(result.valid).toBe(true);
  });

  it('is raised once across passes, apart from a digest mismatch on the same record', async () => {
    await appendChain(storage, 3);
    const index = await appendHashed(storage, testEvidenceId('ev-2'), reviewed());
    await rewriteStoredEnvelope(storage, testEvidenceId('ev-2'), (e) => {
      (e.custodyChain[index] as { actor: string }).actor = 'someone-else@example.com';
    });
    await pass();
    await pass();
    // A second finding on the same record, of a different type.
    await rewriteStoredEnvelope(storage, testEvidenceId('ev-2'), (e) => { e.payload.reason = 'rewritten'; });
    await pass();
    await pass();

    const byType = (await incidents()).map((i) => i.type).sort();
    expect(byType).toEqual(['custody_trail_invalid', 'digest_mismatch']);
  });

  it('the last mirrored entry deleted: the ledger reports mirror_entry_missing', async () => {
    // The envelope alone cannot show this: what is left is a shorter trail
    // that is internally consistent. The ledger row remembers the entry.
    await appendChain(storage, 3);
    await appendHashed(storage, testEvidenceId('ev-2'), reviewed());
    const [row] = await storage.listCustodyEntries(testEvidenceId('ev-2'));
    await rewriteStoredEnvelope(storage, testEvidenceId('ev-2'), (e) => { e.custodyChain.pop(); });

    const { custody } = await pass();

    expect(custody).toEqual([
      // `rowId` is the ledger row's id as text — the platform's column is a
      // bigint, so the verdict carries every row id as a string.
      { type: 'custody_trail_invalid', evidenceId: testEvidenceId('ev-2'), failures: [{ reason: 'mirror_entry_missing', rowId: String(row.id) }] },
    ]);
    expect((await walk()).custodyTrailInvalid).toEqual([testEvidenceId('ev-2')]);
  });

  describe("a 'relinked' entry's relinkDigest is checked against the relink record it names", () => {
    const relinkRecord = (over: Partial<RelinkRecord> = {}): RelinkRecord => ({
      id: 'relink-custody-scan',
      incidentId: 'inc-custody-scan',
      relinkedAt: '2026-09-19T10:00:00.000Z',
      relinkedBy: 'admin@example.com',
      fromSequence: 2,
      toSequence: 2,
      modifiedLinks: [{ evidenceId: testEvidenceId('ev-2'), sequenceNumber: 2, previousChainLink: 'aa', newChainLink: 'bb' }],
      ...over,
    });
    const relinked = (relinkId: string, relinkDigest: string): CustodyEntry => ({
      timestamp: '2026-09-19T10:00:00.000Z',
      actor: 'admin@example.com',
      action: 'relinked',
      systemId: 'tzun-recovery',
      metadata: { incidentId: 'inc-custody-scan', recoveryTier: 'relink', relinkId, relinkDigest },
    });

    it('matches: nothing is raised', async () => {
      await appendChain(storage, 3);
      const record = relinkRecord();
      await storage.storeRelink(record);
      await appendHashed(storage, testEvidenceId('ev-2'), relinked(record.id, computeRelinkDigest(record)));

      const { custody } = await pass();
      expect(custody).toEqual([]);
    });

    it('the relink record no longer has the digest the entry recorded: relink_digest_mismatch', async () => {
      await appendChain(storage, 3);
      const record = relinkRecord();
      await storage.storeRelink(record);
      // The digest of the record as it was before someone widened the range.
      const recorded = computeRelinkDigest({ ...record, toSequence: 1 });
      const index = await appendHashed(storage, testEvidenceId('ev-2'), relinked(record.id, recorded));

      const { custody } = await pass();
      expect(custody).toEqual([
        { type: 'custody_trail_invalid', evidenceId: testEvidenceId('ev-2'), failures: [{ reason: 'relink_digest_mismatch', index }] },
      ]);
    });

    it('the relink record it names is not in the store: relink_record_missing', async () => {
      await appendChain(storage, 3);
      const index = await appendHashed(storage, testEvidenceId('ev-2'), relinked('relink-that-never-was', 'f'.repeat(64)));

      const { custody } = await pass();
      expect(custody).toEqual([
        { type: 'custody_trail_invalid', evidenceId: testEvidenceId('ev-2'), failures: [{ reason: 'relink_record_missing', index }] },
      ]);
    });
  });
});

describe('a store that cannot read its custody ledger', () => {
  it('still gets the envelope check, and neither the pass nor the walk throws', async () => {
    // The platform's chain-scoped scanner view stubs listCustodyEntries to
    // throw; it checks custody in its own chain-status read.
    const storage = new MemoryStorageAdapter();
    await appendChain(storage, 3);
    const index = await appendHashed(storage, testEvidenceId('ev-2'), reviewed());
    await rewriteStoredEnvelope(storage, testEvidenceId('ev-2'), (e) => {
      (e.custodyChain[index] as { actor: string }).actor = 'someone-else@example.com';
    });
    jest.spyOn(storage, 'listCustodyEntries').mockRejectedValue(new Error('not available on this view'));
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const bus = new MonitoringEventBus();
      const events: MonitoringEvent[] = [];
      bus.subscribe((e) => events.push(e));
      await new ScheduledScanner(storage, bus, registry, scannerConfig).runFullPass();

      const custody = events.filter((e): e is CustodyEvent => e.type === 'custody_trail_invalid');
      expect(custody.map((e) => [e.evidenceId, e.failures.map((f) => f.reason)])).toEqual([
        [testEvidenceId('ev-2'), ['entry_hash_mismatch']],
      ]);
      const result = await verifyChainCompleteness(storage, registry, { toSequence: 3 });
      expect(result.custodyTrailInvalid).toEqual([testEvidenceId('ev-2')]);
    } finally {
      errorSpy.mockRestore();
    }
  });
});
