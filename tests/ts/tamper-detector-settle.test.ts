// tests/ts/tamper-detector-settle.test.ts — `runScan()` and
// `close()` wait for the incidents a pass raised to reach storage.
//
// WHY. `MonitoringEventBus.emit` is synchronous and so is
// `TamperDetector.handleEvent`, but the `storage.storeIncident(incident)`
// it starts is not. If `Tzun.runScan()` awaited only the pass, then on an
// adapter with a real round trip (Postgres awaits a SELECT before its INSERT)
// it would resolve with the incident still in flight: a
// `GET /v1/integrity/incidents` right after it would answer `[]`,
// `GET /v1/integrity/status` would answer `'healthy'` beside a summary saying
// `digestMismatches: 1`, and `Tzun.close()` would close the pool under the
// INSERT, so the incident the scanner had just reported would fail to persist
// and the failure would be swallowed by the detector's log-and-continue.
// SQLite and memory hide the ordering, because their `storeIncident` bodies
// run to completion before the first yield.
//
// These tests make the persist visibly asynchronous — a gate the test holds —
// on the memory adapter, so the ordering claim is checked on every CI run
// rather than only under the Postgres gate.
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { TamperDetector } from '../../src/monitoring/tamper-detector';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { Tzun } from '../../src/sdk/index';
import { TamperIncident } from '@tzun/engine';

function gate(): { promise: Promise<void>; open: () => void } {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => { open = resolve; });
  return { promise, open };
}

/** Let every microtask and one macrotask turn run. */
const turn = (): Promise<void> => new Promise((r) => setImmediate(r));

const scanner = {
  batchSize: 100,
  workers: 2,
  mode: 'interval' as const,
  intervalMs: 0,
  verifyAttestation: false,
  verifyChainCompleteness: true,
};

async function bootWithTamperedRecord(): Promise<{ tzun: Tzun; storage: MemoryStorageAdapter }> {
  const tzun = await Tzun.init({
    mode: 'dev',
    verifyReads: false,
    monitoring: { enabled: true, scanner },
  });
  const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { x: 1 }, action: 'approved', reason: 'ok' });
  const storage = tzun.getStorage() as MemoryStorageAdapter;
  // The store is edited behind the SDK — the row itself, not a copy handed
  // out by `retrieve()` — which is what the scanner exists to catch.
  await rewriteStoredEnvelope(storage, r.envelope.payload.evidenceId, (stored) => {
    stored.payload.reason = 'rewritten behind the SDK';
  });
  return { tzun, storage };
}

describe('TamperDetector.settle()', () => {
  let errorSpy: jest.SpyInstance;
  beforeEach(() => { errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {}); });
  afterEach(() => { errorSpy.mockRestore(); });

  it('resolves only once every persist handed to storage has finished, including ones started while it waits', async () => {
    const bus = new MonitoringEventBus();
    const storage = new MemoryStorageAdapter();
    const detector = new TamperDetector(bus, storage);

    const first = gate();
    const second = gate();
    const gates = [first, second];
    const landed: string[] = [];
    const original = storage.storeIncident.bind(storage);
    jest.spyOn(storage, 'storeIncident').mockImplementation(async (incident: TamperIncident) => {
      await gates.shift()!.promise;
      await original(incident);
      landed.push(incident.type);
    });

    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-1', stored: 'a', recomputed: 'b' });
    let settled = false;
    const settling = detector.settle().then(() => { settled = true; });
    await turn();
    expect(settled).toBe(false);

    // A second incident arrives while settle() is already waiting on the first.
    bus.emit({ type: 'sequence_gap', expectedSequence: 2, foundSequence: 4 });
    first.open();
    await turn();
    expect(landed).toEqual(['digest_mismatch']);
    expect(settled).toBe(false);

    second.open();
    await settling;
    expect(settled).toBe(true);
    expect(landed).toEqual(['digest_mismatch', 'sequence_gap']);
    expect((await storage.listIncidents({ status: 'open' })).length).toBe(2);
  });

  it('resolves immediately when nothing is in flight', async () => {
    const detector = new TamperDetector(new MonitoringEventBus(), new MemoryStorageAdapter());
    await expect(detector.settle()).resolves.toBeUndefined();
  });

  it('does not reject when a persist failed — the failure was already logged, and a closer must still proceed', async () => {
    const bus = new MonitoringEventBus();
    const storage = new MemoryStorageAdapter();
    const detector = new TamperDetector(bus, storage);
    jest.spyOn(storage, 'storeIncident').mockRejectedValue(new Error('pool is closed'));

    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-1', stored: 'a', recomputed: 'b' });
    await expect(detector.settle()).resolves.toBeUndefined();
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Failed to persist incident'),
      'pool is closed',
    );
    // Drained: a second settle() has nothing to wait for.
    await expect(detector.settle()).resolves.toBeUndefined();
  });
});

describe('Tzun waits for the incidents a pass raised to reach storage', () => {
  it('runScan() resolves only after the incident row has landed', async () => {
    const { tzun, storage } = await bootWithTamperedRecord();
    try {
      const persist = gate();
      let landed = false;
      const original = storage.storeIncident.bind(storage);
      jest.spyOn(storage, 'storeIncident').mockImplementation(async (incident: TamperIncident) => {
        await persist.promise;
        await original(incident);
        landed = true;
      });

      const passCompleted = new Promise<void>((resolve) => tzun.on('scan.completed', () => resolve()));
      let landedWhenRunScanResolved: boolean | null = null;
      const scan = tzun.runScan().then(() => { landedWhenRunScanResolved = landed; });

      // The pass has run to completion and emitted; the persist is parked
      // behind the gate, so runScan() must not have resolved yet.
      await passCompleted;
      await turn();
      expect(landed).toBe(false);

      persist.open();
      await scan;
      expect(landedWhenRunScanResolved).toBe(true);
      expect((await storage.listIncidents({ status: 'open' })).map((i) => i.type)).toEqual(['digest_mismatch']);
    } finally {
      await tzun.close();
    }
  });

  it('close() lets an in-flight incident land before closing storage', async () => {
    const { tzun, storage } = await bootWithTamperedRecord();
    const persist = gate();
    const order: string[] = [];
    const originalStore = storage.storeIncident.bind(storage);
    jest.spyOn(storage, 'storeIncident').mockImplementation(async (incident: TamperIncident) => {
      await persist.promise;
      await originalStore(incident);
      order.push('incident persisted');
    });
    const originalClose = storage.close.bind(storage);
    jest.spyOn(storage, 'close').mockImplementation(async () => {
      order.push('storage closed');
      await originalClose();
    });

    const passCompleted = new Promise<void>((resolve) => tzun.on('scan.completed', () => resolve()));
    const scan = tzun.runScan();
    await passCompleted;

    // Shut down while the incident is still on its way to storage. A
    // `close()` that reached `storage.close()` immediately would give
    // ['storage closed', 'incident persisted'] — on a real adapter the pool
    // closes under the INSERT, and the incident the pass reported is lost.
    const closing = tzun.close();
    await turn();
    expect(order).toEqual([]);

    persist.open();
    await Promise.all([scan, closing]);
    expect(order).toEqual(['incident persisted', 'storage closed']);
  });
});
