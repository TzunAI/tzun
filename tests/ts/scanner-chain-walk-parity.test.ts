import { testEvidenceId } from './helpers/evidence-id';
/**
 * The scanner reports what `verifyChainCompleteness()` reports.
 *
 * The scanner's chain phase is `verifyChainCompleteness()`, one chain at a
 * time, and its findings become monitoring events. This file pins that the
 * scanner neither drops a finding the walk makes nor keeps rules of its own
 * that could drift from the walk's:
 *
 *   - Parity. On a battery of tampered stores, every finding the walk
 *     reports reaches the bus as the event the scanner uses for it, and
 *     the `scan_completed` counters agree with the walk. The genesis case
 *     covers the first record's `chainLink`, which a walk that compares each
 *     record only to its predecessor never looks at.
 *   - The two findings the walk alone can make. A record rewritten after
 *     capture, its digest recomputed and its links reseated, is a
 *     `digest_superseded` event and a critical incident, counted in
 *     `issuesFound`. A `capturedAt` running backwards is a
 *     `captured_at_regression` event and a warning incident, NOT counted in
 *     `issuesFound` — suspicious, not proof. Each has a companion case showing
 *     the walk reports the finding in the store the scanner is given.
 *
 * ADAPTERS. The two findings and their companions run on memory and SQLite,
 * and on Postgres when the Postgres legs run (tests/ts/helpers/postgres-test-db.ts).
 * The Postgres leg works in a schema of its own per case and drops only that.
 * The parity battery deletes rows, which the SQL adapters' append-only
 * triggers refuse, so it runs on memory: the rules under test are the walk's,
 * not the adapter's.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  EvidenceChain,
  EvidenceEnvelope,
  MonitoringEvent,
  ScanCompletedEvent,
  ScannerConfig,
  SchemaRegistry,
  StorageAdapter,
  TamperIncident,
  assembleEnvelope,
  canonicalSerialize,
  computeDigest,
  verifyChainCompleteness,
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

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

interface Opened {
  storage: StorageAdapter;
  close: () => Promise<void>;
}

interface Leg {
  name: string;
  open: () => Promise<Opened>;
}

const memoryLeg: Leg = {
  name: 'memory',
  open: async () => {
    const storage = new MemoryStorageAdapter();
    return { storage, close: async () => storage.close() };
  },
};

const sqliteLeg: Leg = {
  name: 'sqlite',
  open: async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-scan-'));
    const storage = new SqliteStorageAdapter(path.join(dir, 'scan.db'));
    return {
      storage,
      close: async () => {
        await storage.close();
        fs.rmSync(dir, { recursive: true, force: true });
      },
    };
  },
};

const postgresLeg: Leg = {
  name: 'postgres',
  open: async () => {
    // A schema of this case's own, reached through the pool's search_path: the
    // adapter's DDL is unqualified, so its tables, functions and triggers all
    // land here, and dropping it removes exactly what this case created.
    const schema = await pgCaseSchema('scanner_chain_walk');
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
};

const legs: Leg[] = PG_TESTS_ENABLED ? [memoryLeg, sqliteLeg, postgresLeg] : [memoryLeg, sqliteLeg];

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

/** Append `n` correctly linked records, `ev-1`..`ev-n`, through `store()`. */
async function appendChain(
  storage: StorageAdapter,
  n: number,
  capturedAt?: (i: number) => string,
): Promise<EvidenceEnvelope[]> {
  const out: EvidenceEnvelope[] = [];
  let previousDigest: string | undefined;
  for (let i = 1; i <= n; i++) {
    const envelope = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'sys-chain-walk',
        aiOutput: { recommendation: `r${i}` },
        action: 'approved',
        reason: `reason ${i}`,
      }, { previousDigest: previousDigest, sequenceNumber: i, signoffExpectation: null, capturedAt: capturedAt?.(i), evidenceId: testEvidenceId(`ev-${i}`) });
    await storage.store(envelope);
    previousDigest = envelope.integrity.canonicalDigest;
    out.push(envelope);
  }
  return out;
}

function linkOnto(previousDigest: string, digest: string): string | null {
  const chain = new EvidenceChain();
  chain.restore(previousDigest);
  return chain.computeLink(digest);
}

/**
 * The rewrite-and-reseat, completed: rewrite `ev-k`'s payload, recompute its
 * digest, relink it onto its predecessor, and relink its successor onto it.
 * `chainLink` is outside the hashed field set, so both relinks are free to an
 * attacker with store-write access. Afterwards every record hashes to the
 * digest it carries and every link recomputes — nothing computed from the
 * store's present state can see the edit.
 */
async function rewriteAndReseat(storage: StorageAdapter, chain: EvidenceEnvelope[], k: number): Promise<string> {
  const victim = chain[k - 1];
  let forgedDigest = '';
  await rewriteStoredEnvelope(storage, victim.payload.evidenceId, (e) => {
    e.payload.reason = 'approved — the approver never wrote this';
    forgedDigest = computeDigest(
      canonicalSerialize(e.payload as unknown as Record<string, unknown>, registry.get('v1.0')!.hashedFieldSet),
    );
    e.integrity.canonicalDigest = forgedDigest;
    e.integrity.chainLink = linkOnto(chain[k - 2].integrity.canonicalDigest, forgedDigest);
  });
  const successor = chain[k];
  if (successor) {
    await rewriteStoredEnvelope(storage, successor.payload.evidenceId, (e) => {
      e.integrity.chainLink = linkOnto(forgedDigest, successor.integrity.canonicalDigest);
    });
  }
  return victim.payload.evidenceId;
}

// ---------------------------------------------------------------------------
// Running a pass
// ---------------------------------------------------------------------------

interface Pass {
  events: MonitoringEvent[];
  incidents: TamperIncident[];
  completed: ScanCompletedEvent;
}

/** One pass of the scanner as `Tzun.init()` wires it: bus → TamperDetector. */
async function scan(storage: StorageAdapter): Promise<Pass> {
  const bus = new MonitoringEventBus();
  const detector = new TamperDetector(bus, storage);
  const events: MonitoringEvent[] = [];
  const incidents: TamperIncident[] = [];
  bus.subscribe((event) => events.push(event));
  detector.onIncident((incident) => incidents.push(incident));

  await new ScheduledScanner(storage, bus, registry, scannerConfig).runFullPass();
  await detector.settle();

  const completed = events.filter((e): e is ScanCompletedEvent => e.type === 'scan_completed');
  expect(completed).toHaveLength(1);
  return { events, incidents, completed: completed[0] };
}

/** The walk the scanner is meant to agree with, over the same chain and range. */
async function walk(storage: StorageAdapter) {
  return verifyChainCompleteness(storage, registry, {
    fromSequence: 1,
    toSequence: await storage.getLastSequence(),
    chainId: await storage.getActiveChainId(),
  });
}

const byNumber = (a: number, b: number) => a - b;

/** Every sequence number the pass's sequence_gap events say is missing. */
function missingNumbers(events: MonitoringEvent[]): number[] {
  const out: number[] = [];
  for (const e of events) {
    if (e.type !== 'sequence_gap') continue;
    for (let s = e.expectedSequence; s < e.foundSequence; s++) out.push(s);
  }
  return out.sort(byNumber);
}

// ---------------------------------------------------------------------------
// Parity: every finding the walk reports, the scanner emits
// ---------------------------------------------------------------------------

describe('the scanner reports every finding verifyChainCompleteness reports', () => {
  const deleteRows = (storage: StorageAdapter, ...ids: string[]) => {
    const rows = (storage as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes;
    for (const id of ids) expect(rows.delete(id)).toBe(true);
  };

  const scenarios: Array<{ name: string; build: (s: MemoryStorageAdapter) => Promise<void> }> = [
    { name: 'a clean chain', build: async (s) => { await appendChain(s, 6); } },
    {
      name: 'one record deleted mid-chain',
      build: async (s) => { await appendChain(s, 6); deleteRows(s, testEvidenceId('ev-3')); },
    },
    {
      name: 'two separate runs deleted',
      build: async (s) => { await appendChain(s, 7); deleteRows(s, testEvidenceId('ev-2'), testEvidenceId('ev-4'), testEvidenceId('ev-5')); },
    },
    {
      name: 'the tail deleted',
      build: async (s) => { await appendChain(s, 6); deleteRows(s, testEvidenceId('ev-5'), testEvidenceId('ev-6')); },
    },
    {
      name: 'the head deleted',
      build: async (s) => { await appendChain(s, 6); deleteRows(s, testEvidenceId('ev-1'), testEvidenceId('ev-2')); },
    },
    {
      // The chain-state counter survives the deletes, so the walk's bound
      // still says six records were written.
      name: 'every record deleted',
      build: async (s) => {
        await appendChain(s, 6);
        deleteRows(s, testEvidenceId('ev-1'), testEvidenceId('ev-2'), testEvidenceId('ev-3'), testEvidenceId('ev-4'), testEvidenceId('ev-5'), testEvidenceId('ev-6'));
      },
    },
    {
      name: 'a forged record under a sequence number already in use',
      build: async (s) => {
        const chain = await appendChain(s, 5);
        // A store-write attacker who stepped around the one-record-per-position
        // rule (the SQL adapters' envelopes_position index; this adapter's
        // position map), as only the store's owner can.
        (s as unknown as { positions: Map<string, string> }).positions.clear();
        await s.store(
          assembleEnvelope({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 'sys-chain-walk', aiOutput: { recommendation: 'forged' }, action: 'approved', reason: 'inserted' }, { previousDigest: chain[2].integrity.canonicalDigest, sequenceNumber: 3, signoffExpectation: null, evidenceId: testEvidenceId('forged') }),
        );
      },
    },
    {
      name: 'a chain link rewritten',
      build: async (s) => {
        await appendChain(s, 5);
        await rewriteStoredEnvelope(s, testEvidenceId('ev-3'), (e) => { e.integrity.chainLink = 'deadbeef'; });
      },
    },
    {
      name: 'a payload rewritten with its digest left stale',
      build: async (s) => {
        await appendChain(s, 5);
        await rewriteStoredEnvelope(s, testEvidenceId('ev-3'), (e) => { e.payload.reason = 'TAMPERED'; });
      },
    },
    {
      // A walk that only compares a record to the one before it never looks
      // at the first record's link. A genesis record has no predecessor and
      // its link is null; one carrying a link was spliced onto something.
      name: 'the genesis record carrying a chain link',
      build: async (s) => {
        await appendChain(s, 4);
        await rewriteStoredEnvelope(s, testEvidenceId('ev-1'), (e) => { e.integrity.chainLink = 'ab'.repeat(32); });
      },
    },
    {
      // The scanner checks custody in Phase 1, the walk in its own pass; both
      // must name the record.
      name: 'a custody entry rewritten after it was recorded',
      build: async (s) => {
        await appendChain(s, 4);
        await s.appendCustodyEntry(testEvidenceId('ev-3'), {
          timestamp: '2026-09-19T10:00:00.000Z',
          actor: 'op@example.com',
          action: 'reviewed',
          systemId: 'tzun-recovery',
        });
        await rewriteStoredEnvelope(s, testEvidenceId('ev-3'), (e) => {
          (e.custodyChain[e.custodyChain.length - 1] as { actor: string }).actor = 'someone-else';
        });
      },
    },
    {
      name: 'capturedAt running backwards at two places',
      build: async (s) => {
        const at = ['10:00:00', '09:00:00', '10:00:30', '08:00:00', '10:01:00'];
        await appendChain(s, 5, (i) => `2026-09-17T${at[i - 1]}.000Z`);
      },
    },
    {
      name: 'a record rewritten and reseated, its successor left alone',
      build: async (s) => {
        const chain = await appendChain(s, 5);
        await rewriteStoredEnvelope(s, testEvidenceId('ev-3'), (e) => {
          e.payload.reason = 'rewritten';
          const digest = computeDigest(
            canonicalSerialize(e.payload as unknown as Record<string, unknown>, registry.get('v1.0')!.hashedFieldSet),
          );
          e.integrity.canonicalDigest = digest;
          e.integrity.chainLink = linkOnto(chain[1].integrity.canonicalDigest, digest);
        });
      },
    },
  ];

  it.each(scenarios)('$name', async ({ build }) => {
    const storage = new MemoryStorageAdapter();
    await build(storage);

    const result = await walk(storage);
    const { events, completed } = await scan(storage);

    const idsOf = (type: MonitoringEvent['type']) =>
      events.filter((e) => e.type === type).map((e) => (e as { evidenceId: string }).evidenceId).sort();

    expect({
      brokenLinks: idsOf('chain_break'),
      duplicateSequences: events
        .filter((e): e is Extract<MonitoringEvent, { type: 'duplicate_sequence' }> => e.type === 'duplicate_sequence')
        .map((e) => e.sequenceNumber)
        .sort(byNumber),
      sequenceGaps: missingNumbers(events),
      digestMismatches: idsOf('digest_mismatch'),
      digestSuperseded: idsOf('digest_superseded'),
      timeRegressions: idsOf('captured_at_regression'),
      custodyTrailInvalid: idsOf('custody_trail_invalid'),
    }).toEqual({
      brokenLinks: [...result.brokenLinks].sort(),
      duplicateSequences: [...result.duplicateSequences].sort(byNumber),
      sequenceGaps: [...result.sequenceGaps].sort(byNumber),
      digestMismatches: [...result.digestMismatches].sort(),
      digestSuperseded: [...result.digestSuperseded].sort(),
      timeRegressions: [...result.timeRegressions].sort(),
      custodyTrailInvalid: [...result.custodyTrailInvalid].sort(),
    });

    expect({
      chainBreaks: completed.chainBreaks,
      duplicateSequences: completed.duplicateSequences,
      digestMismatches: completed.digestMismatches,
      digestSuperseded: completed.digestSuperseded,
      timeRegressions: completed.timeRegressions,
      custodyTrailInvalid: completed.custodyTrailInvalid,
    }).toEqual({
      chainBreaks: result.brokenLinks.length,
      duplicateSequences: result.duplicateSequences.length,
      digestMismatches: result.digestMismatches.length,
      digestSuperseded: result.digestSuperseded.length,
      timeRegressions: result.timeRegressions.length,
      custodyTrailInvalid: result.custodyTrailInvalid.length,
    });
  });

  it('reports a genesis chain_break with the record, its sequence number and no predecessor', async () => {
    const storage = new MemoryStorageAdapter();
    await appendChain(storage, 3);
    await rewriteStoredEnvelope(storage, testEvidenceId('ev-1'), (e) => { e.integrity.chainLink = 'ab'.repeat(32); });

    const { events, incidents, completed } = await scan(storage);

    expect(events.filter((e) => e.type === 'chain_break')).toEqual([
      { type: 'chain_break', evidenceId: testEvidenceId('ev-1'), sequenceNumber: 1, expectedPrevDigest: '' },
    ]);
    expect(incidents.map((i) => [i.type, i.severity, i.affectedRecords])).toEqual([
      ['chain_break', 'critical', [testEvidenceId('ev-1')]],
    ]);
    expect(completed.issuesFound).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// The two findings only verifyChainCompleteness makes
// ---------------------------------------------------------------------------

describe.each(legs)('findings with no scanner event yet — $name adapter', (leg) => {
  let opened: Opened;
  beforeEach(async () => { opened = await leg.open(); });
  afterEach(async () => { await opened.close(); });

  describe('a record rewritten after capture, its digest recomputed and its links reseated', () => {
    it('is in the store: the walk reports it superseded, and nothing else sees it', async () => {
      const { storage } = opened;
      const chain = await appendChain(storage, 5);
      const victimId = await rewriteAndReseat(storage, chain, 3);

      const result = await walk(storage);
      expect(result.digestSuperseded).toEqual([victimId]);
      // The attack's signature: it hashes to its digest and every link holds.
      expect(result.digestMismatches).toEqual([]);
      expect(result.brokenLinks).toEqual([]);
      expect(result.valid).toBe(false);
    });

    it('is a digest_superseded event and a critical incident naming the rewritten record', async () => {
      const { storage } = opened;
      const chain = await appendChain(storage, 5);
      const capturedDigest = chain[2].integrity.canonicalDigest;
      const victimId = await rewriteAndReseat(storage, chain, 3);
      const currentDigest = (await storage.retrieve(victimId))!.integrity.canonicalDigest;
      expect(currentDigest).not.toBe(capturedDigest);

      const { events, incidents, completed } = await scan(storage);

      expect(events.filter((e) => e.type === 'digest_superseded')).toEqual([
        { type: 'digest_superseded', evidenceId: victimId, sequenceNumber: 3, capturedDigest, currentDigest },
      ]);
      // Nothing computed from present state sees the edit. Two stores of the
      // past do: the capture revision, and the evidence log, whose leaf is
      // the digest the record was logged with.
      expect(incidents.map((i) => [i.type, i.severity, i.affectedRecords]).sort()).toEqual([
        ['digest_differs_from_logged_leaf', 'critical', [victimId]],
        ['digest_superseded', 'critical', [victimId]],
      ]);
      const superseded = incidents.find((i) => i.type === 'digest_superseded')!;
      expect(superseded.affectedSequenceRange).toEqual({ from: 3, to: 3 });
      expect(superseded.details).toContain(capturedDigest);
      expect(superseded.details).toContain(currentDigest);
      expect(events.filter((e) => e.type === 'digest_differs_from_logged_leaf')).toEqual([
        expect.objectContaining({ evidenceId: victimId, sequenceNumber: 3, loggedDigest: capturedDigest, currentDigest }),
      ]);
      // A superseded record makes `valid` false, so the pass is not clean.
      expect(completed.digestSuperseded).toBe(1);
      expect(completed.logFindings).toBe(1);
      expect(completed.issuesFound).toBe(2);
    });
  });

  describe('capturedAt running backwards along the chain', () => {
    // ev-2 was minted on a clock set back an hour.
    const times = ['2026-09-17T10:00:00.000Z', '2026-09-17T09:00:00.000Z', '2026-09-17T10:00:11.000Z'];

    it('is in the store: the walk reports the regression, and does not call the chain invalid', async () => {
      const { storage } = opened;
      await appendChain(storage, 3, (i) => times[i - 1]);

      const result = await walk(storage);
      expect(result.timeRegressions).toEqual([testEvidenceId('ev-2')]);
      expect(result.valid).toBe(true);
    });

    it('is a captured_at_regression event and a warning incident, not counted as an issue', async () => {
      const { storage } = opened;
      await appendChain(storage, 3, (i) => times[i - 1]);

      const { events, incidents, completed } = await scan(storage);

      expect(events.filter((e) => e.type === 'captured_at_regression')).toEqual([
        { type: 'captured_at_regression', evidenceId: testEvidenceId('ev-2'), sequenceNumber: 2, capturedAt: times[1] },
      ]);
      // Suspicious, not proof: an NTP correction produces one honestly. The
      // SDK's level below critical, and wording that does not assert tampering.
      expect(incidents.map((i) => [i.type, i.severity, i.affectedRecords])).toEqual([
        ['captured_at_regression', 'warning', [testEvidenceId('ev-2')]],
      ]);
      expect(incidents[0].details).toContain('not proof of tampering');
      expect(incidents[0].details).toContain(times[1]);
      // Not part of `valid`, so not part of whether the pass was clean.
      expect(completed.timeRegressions).toBe(1);
      expect(completed.issuesFound).toBe(0);
    });
  });
});
