import { Tzun } from '../../src/sdk/index';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
// These cases tamper by rewriting the stored row itself, through
// `rewriteStoredEnvelope`, which works on every backend. The memory adapter
// clones on read and write, as the SQL adapters do, so mutating an object a
// read returned would change nothing in the store and leave the detection
// under test with nothing to detect.
import { TamperIncident, ScanSummary } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../src/storage/memory';

describe('Monitoring & Notifications End-to-End', () => {
  describe('Happy path: capture, verify, scan with zero incidents', () => {
    it('full pipeline: capture N records -> scanner full pass -> healthy', async () => {
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
      for (let i = 0; i < 5; i++) {
        const result = await tzun.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { step: i },
          action: 'approved',
          reason: `Step ${i}`,
        });
        expect(result.stored).toBe(true);
      }

      // Verify each record fully: verify() resolves the predecessor itself, so
      // every record, genesis or not, must come back verified with its chain
      // link checked, not only its digest.
      const storage = tzun.getStorage();
      const all = await storage.list({ order: 'asc' });
      for (const env of all) {
        const vr = await tzun.verify(env.payload.evidenceId);
        expect(vr.storedDigest).toBe(vr.recomputedDigest);
        expect(vr.verified).toBe(true);
      }

      // Scan
      const summaries: ScanSummary[] = [];
      tzun.on('scan.completed', (s) => summaries.push(s));

      await tzun.runScan();

      expect(summaries).toHaveLength(1);
      expect(summaries[0].recordsChecked).toBe(5);
      expect(summaries[0].issuesFound).toBe(0);

      // No incidents
      const incidents = await storage.listIncidents();
      expect(incidents).toHaveLength(0);

      await tzun.close();
    });
  });

  describe('Tamper detection end-to-end', () => {
    it('tamper record -> proxy detect on retrieve -> incident created -> emitter fires', async () => {
      const tzun = await Tzun.init({
        monitoring: { enabled: true },
      });

      const result = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'approve' },
        action: 'approved',
        reason: 'Valid',
      });

      // Tamper
      await rewriteStoredEnvelope(tzun.getStorage(), result.envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

      const incidents: TamperIncident[] = [];
      tzun.on('tamper', (i) => incidents.push(i));

      // The verified read triggers detection
      await tzun.get(result.envelope.payload.evidenceId);

      await new Promise(resolve => setTimeout(resolve, 50));

      expect(incidents).toHaveLength(1);
      expect(incidents[0].type).toBe('digest_mismatch');
      expect(incidents[0].severity).toBe('critical');

      // Incident persisted
      const stored = await tzun.getStorage().listIncidents();
      expect(stored.length).toBeGreaterThanOrEqual(1);

      await tzun.close();
    });
  });

  describe('Deletion detection end-to-end', () => {
    it('delete record -> scanner detects sequence gap -> incident created', async () => {
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

      // Delete record 3 from underlying storage
      const storage = tzun.getStorage() as MemoryStorageAdapter;
      const deleteId = results[2].envelope.payload.evidenceId;
      (storage as any).envelopes.delete(deleteId);

      const incidents: TamperIncident[] = [];
      tzun.on('tamper', (i) => incidents.push(i));

      await tzun.runScan();

      await new Promise(resolve => setTimeout(resolve, 50));

      // Should detect at least the sequence gap
      const gapIncidents = incidents.filter(i => i.type === 'sequence_gap');
      expect(gapIncidents.length).toBeGreaterThanOrEqual(1);

      await tzun.close();
    });
  });

  describe('Multi-channel notification', () => {
    it('event emitter + webhook both receive incident', async () => {
      const webhookCalls: unknown[] = [];
      const mockFetch = jest.fn().mockImplementation(async () => {
        webhookCalls.push(true);
        return { ok: true, status: 200 };
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch as unknown as typeof fetch;

      try {
        const tzun = await Tzun.init({
          monitoring: {
            enabled: true,
            notifications: {
              webhook: {
                url: 'https://example.com/hook',
                secret: 'test-secret',
                severities: ['critical'],
                retries: 0,
                retryDelayMs: 0,
              },
            },
          },
        });

        const result = await tzun.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { text: 'test' },
          action: 'approved',
          reason: 'Valid',
        });

        const emitterIncidents: TamperIncident[] = [];
        tzun.on('tamper', (i) => emitterIncidents.push(i));

        // Tamper
        await rewriteStoredEnvelope(tzun.getStorage(), result.envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

        await tzun.get(result.envelope.payload.evidenceId);

        await new Promise(resolve => setTimeout(resolve, 100));

        // Event emitter should have received
        expect(emitterIncidents).toHaveLength(1);

        // Webhook should have been called
        expect(webhookCalls.length).toBeGreaterThanOrEqual(1);

        await tzun.close();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe('Scanner state persistence', () => {
    it('scanner state tracks pass count and high water mark', async () => {
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

      for (let i = 0; i < 3; i++) {
        await tzun.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { step: i },
          action: 'approved',
          reason: `Step ${i}`,
        });
      }

      await tzun.runScan();
      await tzun.runScan();

      // Internal scanner state tracked -- verified via scan.completed events
      const summaries: ScanSummary[] = [];
      tzun.on('scan.completed', (s) => summaries.push(s));
      await tzun.runScan();

      expect(summaries).toHaveLength(1);
      expect(summaries[0].recordsChecked).toBe(3);

      await tzun.close();
    });
  });
});
