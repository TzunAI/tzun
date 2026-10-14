import { testEvidenceId } from './helpers/evidence-id';
/**
 * A finding that already has an incident is not raised again, whatever that
 * incident's status. The pass records that it observed the finding again.
 *
 * The scanner reports every finding on every pass, and a tampered record stays
 * tampered — so without this, one edited row would open a fresh critical
 * incident per scan interval, forever, and acknowledging it would do nothing:
 * the next pass would open another. TamperDetector keys a finding as the
 * platform does: the incident type, and what it is about — the records it
 * names, else its sequence range, else the chain.
 *
 * A RESOLVED incident is no exception. A hashed record can never be repaired in
 * place, so "resolved" on a tamper finding means a human reviewed it, not that
 * it is gone: if the next pass raised it again, resolving it would put the
 * store back to 'compromised' and the same finding would have to be resolved
 * again, forever. The rule errs on the side of flagging red or amber rather
 * than going green too early, and the hosted service implements the same rule
 * (one incident per finding, `last_observed_at` stamped by the dedupe path).
 * `lastObservedAt` is what holds the store at 'degraded' while a reviewed
 * finding is still there, and what lets it reach 'healthy' once a pass stops
 * seeing it.
 *
 * ADAPTERS. Memory and SQLite always; Postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema created for the case and
 * dropped after it.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  EvidenceEnvelope,
  ScannerConfig,
  SchemaRegistry,
  StorageAdapter,
  TamperIncident,
  assembleEnvelope,
} from '@tzun/engine';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { ScheduledScanner } from '../../src/monitoring/scheduled-scanner';
import { TamperDetector } from '../../src/monitoring/tamper-detector';
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
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-dedupe-'));
      const storage = new SqliteStorageAdapter(path.join(dir, 'dedupe.db'));
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
      const schema = await pgCaseSchema('dedupe');
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
    const envelope = assembleEnvelope({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 'sys-dedupe', aiOutput: { r: i }, action: 'approved', reason: `reason ${i}` }, { previousDigest: previousDigest, sequenceNumber: i, signoffExpectation: null, evidenceId: testEvidenceId(`ev-${i}`) });
    await storage.store(envelope);
    previousDigest = envelope.integrity.canonicalDigest;
    out.push(envelope);
  }
  return out;
}

describe.each(legs)('a finding with an incident being handled is not raised again — $name adapter', (leg) => {
  let opened: Opened;
  let detector: TamperDetector;
  let scanner: ScheduledScanner;

  beforeEach(async () => {
    opened = await leg.open();
    // One long-lived bus, detector and scanner over the store, as Tzun.init()
    // wires them, so successive passes are what a running scanner does.
    const bus = new MonitoringEventBus();
    detector = new TamperDetector(bus, opened.storage);
    scanner = new ScheduledScanner(opened.storage, bus, registry, scannerConfig);
  });
  afterEach(async () => {
    await detector.settle();
    await opened.close();
  });

  const pass = async (): Promise<void> => {
    await scanner.runFullPass();
    await detector.settle();
  };

  const incidents = async (): Promise<TamperIncident[]> => opened.storage.listIncidents();

  it('three passes over one tampered record give exactly one incident', async () => {
    await appendChain(opened.storage, 3);
    await rewriteStoredEnvelope(opened.storage, testEvidenceId('ev-2'), (e) => { e.payload.reason = 'rewritten'; });

    await pass();
    await pass();
    await pass();

    const all = await incidents();
    expect(all.map((i) => [i.type, i.status, i.affectedRecords])).toEqual([
      ['digest_mismatch', 'open', [testEvidenceId('ev-2')]],
    ]);
  });

  it('an acknowledged incident is not raised again', async () => {
    await appendChain(opened.storage, 3);
    await rewriteStoredEnvelope(opened.storage, testEvidenceId('ev-2'), (e) => { e.payload.reason = 'rewritten'; });
    await pass();
    const [first] = await incidents();
    await opened.storage.updateIncidentStatus(first.id, 'acknowledged');

    await pass();
    await pass();

    const all = await incidents();
    expect(all.map((i) => [i.id, i.status])).toEqual([[first.id, 'acknowledged']]);
  });

  it('an in_progress incident is not raised again', async () => {
    // The platform moves an acknowledged incident to 'in_progress' when a
    // recovery action starts on it. The SDK never
    // writes that status and reads it back from a store the platform also
    // writes; a recovery under way is being handled, so the finding must not
    // open another incident beside the one being worked on.
    await appendChain(opened.storage, 3);
    await rewriteStoredEnvelope(opened.storage, testEvidenceId('ev-2'), (e) => { e.payload.reason = 'rewritten'; });
    await pass();
    const [first] = await incidents();
    await opened.storage.updateIncidentStatus(first.id, 'in_progress');

    await pass();
    await pass();

    const all = await incidents();
    expect(all.map((i) => [i.id, i.status])).toEqual([[first.id, 'in_progress']]);
  });

  it('a resolved incident is NOT raised again — the finding is re-observed instead', async () => {
    await appendChain(opened.storage, 3);
    await rewriteStoredEnvelope(opened.storage, testEvidenceId('ev-2'), (e) => { e.payload.reason = 'rewritten'; });
    await pass();
    const [first] = await incidents();
    expect(first.lastObservedAt).toBeDefined();
    await opened.storage.updateIncidentStatus(first.id, 'resolved', {
      resolvedBy: 'op@example.com',
      resolutionNotes: 'looked at it',
    });

    await pass();
    await pass();

    const all = await incidents();
    expect(all.map((i) => [i.id, i.type, i.status, i.affectedRecords])).toEqual([
      [first.id, 'digest_mismatch', 'resolved', [testEvidenceId('ev-2')]],
    ]);
    // The observation moved forward; the sign-off the operator left did not.
    expect(all[0].lastObservedAt! >= first.lastObservedAt!).toBe(true);
    expect(all[0].resolvedBy).toBe('op@example.com');
    expect(all[0].resolutionNotes).toBe('looked at it');
    expect(all[0].resolvedAt).toBe(first.resolvedAt ?? all[0].resolvedAt);
  });

  it('every pass stamps the observation forward, on any status', async () => {
    await appendChain(opened.storage, 3);
    await rewriteStoredEnvelope(opened.storage, testEvidenceId('ev-2'), (e) => { e.payload.reason = 'rewritten'; });
    await pass();
    const [raised] = await incidents();

    for (const status of ['acknowledged', 'in_progress', 'resolved'] as const) {
      await opened.storage.updateIncidentStatus(raised.id, status);
      const before = (await incidents())[0].lastObservedAt!;
      // A millisecond of clearance so the ISO strings can differ at all.
      await new Promise((r) => setTimeout(r, 2));
      await pass();
      const after = (await incidents())[0];
      expect(after.id).toBe(raised.id);
      expect(after.status).toBe(status);
      expect(after.lastObservedAt! > before).toBe(true);
    }
    expect(await incidents()).toHaveLength(1);
  });

  it('a finding that goes away stops being observed, and the incident keeps its last sighting', async () => {
    await appendChain(opened.storage, 3);
    await rewriteStoredEnvelope(opened.storage, testEvidenceId('ev-2'), (e) => { e.payload.reason = 'rewritten'; });
    await pass();
    const [raised] = await incidents();
    await opened.storage.updateIncidentStatus(raised.id, 'resolved');
    await pass();
    const observed = (await incidents())[0].lastObservedAt!;

    // Put the record back exactly as appendChain wrote it, so its stored digest
    // recomputes again: the finding is genuinely gone.
    await rewriteStoredEnvelope(opened.storage, testEvidenceId('ev-2'), (e) => { e.payload.reason = 'reason 2'; });
    await new Promise((r) => setTimeout(r, 2));
    await pass();

    const all = await incidents();
    expect(all).toHaveLength(1);
    // Frozen at the last pass that actually saw it — which is what lets
    // computeIntegrityStatus tell this store from one where it is still there.
    expect(all[0].lastObservedAt).toBe(observed);
  });

  it('two different findings on the same record give two incidents', async () => {
    await appendChain(opened.storage, 3);
    // Payload rewritten with its digest left stale (digest_mismatch), and its
    // link broken (chain_break): two findings, one record.
    await rewriteStoredEnvelope(opened.storage, testEvidenceId('ev-2'), (e) => {
      e.payload.reason = 'rewritten';
      e.integrity.chainLink = 'ab'.repeat(32);
    });

    await pass();
    await pass();

    const all = await incidents();
    expect(all.map((i) => [i.type, i.affectedRecords]).sort()).toEqual([
      ['chain_break', [testEvidenceId('ev-2')]],
      ['digest_mismatch', [testEvidenceId('ev-2')]],
    ]);
  });
});
