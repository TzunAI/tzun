import { Tzun } from '../../src/sdk/index';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
// These cases tamper by rewriting the stored row itself, through
// `rewriteStoredEnvelope`, which works on every backend. The memory adapter
// clones on read and write, as the SQL adapters do, so mutating an object a
// read returned would change nothing in the store and leave the detection
// under test with nothing to detect.
import { TamperIncident, ScanSummary } from '@tzun/engine';

describe('Monitoring SDK Integration', () => {
  it('dev mode defaults to monitoring disabled', async () => {
    const tzun = await Tzun.init();
    expect((tzun as unknown as { eventBus: unknown }).eventBus).toBeNull();
    // getStorage() is the configured adapter, whether or not reads go through
    // the verifying proxy.
    expect(tzun.getStorage().constructor.name).toBe('MemoryStorageAdapter');
    await tzun.close();
  });

  it('monitoring can be explicitly enabled in dev mode', async () => {
    const tzun = await Tzun.init({
      monitoring: {
        enabled: true,
      },
    });
    expect((tzun as unknown as { eventBus: unknown }).eventBus).not.toBeNull();
    expect((tzun as unknown as { storage: object }).storage.constructor.name).toBe('VerifyingStorageProxy');
    await tzun.close();
  });

  it('on("tamper") receives TamperIncident when storage proxy detects tampering', async () => {
    const tzun = await Tzun.init({
      monitoring: {
        enabled: true,
      },
    });

    // Capture a record
    const captureResult = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { recommendation: 'approve' },
      action: 'approved',
      reason: 'Valid',
    });
    expect(captureResult.stored).toBe(true);

    // Register tamper listener
    const incidents: TamperIncident[] = [];
    tzun.on('tamper', (incident) => incidents.push(incident));

    // Tamper with the stored record by rewriting the row behind the proxy
    await rewriteStoredEnvelope(tzun.getStorage(), captureResult.envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

    // The read is verified by the proxy
    await tzun.get(captureResult.envelope.payload.evidenceId);

    // Allow async processing
    await new Promise(resolve => setTimeout(resolve, 50));

    expect(incidents).toHaveLength(1);
    expect(incidents[0].type).toBe('digest_mismatch');

    await tzun.close();
  });

  it('on("scan.completed") receives ScanSummary after scanner full pass', async () => {
    const tzun = await Tzun.init({
      verifyReads: false,
      monitoring: {
        enabled: true,
        scanner: {
          batchSize: 100,
          workers: 2,
          mode: 'interval',
          intervalMs: 0,
          verifyAttestation: false,
          verifyChainCompleteness: true,
        },
      },
    });

    // Capture some records
    for (let i = 0; i < 3; i++) {
      await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { step: i },
        action: 'approved',
        reason: `Step ${i}`,
      });
    }

    const summaries: ScanSummary[] = [];
    tzun.on('scan.completed', (summary) => summaries.push(summary));

    // Run a manual scan pass
    await tzun.runScan();

    expect(summaries).toHaveLength(1);
    expect(summaries[0].recordsChecked).toBe(3);
    expect(summaries[0].issuesFound).toBe(0);
    // The public summary IS the pass the scanner recorded — the same object
    // `GET /v1/integrity/status` reports as `lastFullScan` — so
    // `tzun.on('scan.completed')` and the HTTP endpoint give one answer to
    // "what did the last pass do": the same passNumber (1 on the first pass),
    // the same completedAt and the same presence counts.
    expect(summaries[0].passNumber).toBe(1);
    expect(summaries[0]).toEqual(tzun.getScannerState()!.lastCompletedPass);

    await tzun.close();
  });

  it('monitoring proxy + scanner: end-to-end tamper detection', async () => {
    const tzun = await Tzun.init({
      monitoring: {
        enabled: true,
        scanner: {
          batchSize: 100,
          workers: 2,
          mode: 'interval',
          intervalMs: 0,
          verifyAttestation: false,
          verifyChainCompleteness: true,
        },
      },
    });

    // Capture records
    const results = [];
    for (let i = 0; i < 5; i++) {
      const r = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { step: i },
        action: 'approved',
        reason: `Step ${i}`,
      });
      results.push(r);
    }

    // Tamper with a record
    await rewriteStoredEnvelope(tzun.getStorage(), results[2].envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

    // Scanner should detect it
    const incidents: TamperIncident[] = [];
    tzun.on('tamper', (incident) => incidents.push(incident));

    await tzun.runScan();

    // Allow async processing
    await new Promise(resolve => setTimeout(resolve, 50));

    // At least one incident should be created (digest mismatch from scanner)
    expect(incidents.length).toBeGreaterThanOrEqual(1);
    const mismatchIncidents = incidents.filter(i => i.type === 'digest_mismatch');
    expect(mismatchIncidents.length).toBeGreaterThanOrEqual(1);

    await tzun.close();
  });

  it('close() stops the scanner', async () => {
    const tzun = await Tzun.init({
      verifyReads: false,
      monitoring: {
        enabled: true,
        scanner: {
          batchSize: 100,
          workers: 2,
          mode: 'interval',
          intervalMs: 100000, // long interval
          verifyAttestation: false,
          verifyChainCompleteness: false,
        },
      },
    });

    // close() should not hang
    await tzun.close();
  });

  it('monitoring disabled: on() and off() are safe no-ops', async () => {
    const tzun = await Tzun.init();

    const handler = (_incident: TamperIncident) => {};
    // Should not throw
    tzun.on('tamper', handler);
    tzun.off('tamper', handler);

    await tzun.close();
  });
});
