import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const captureInput = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', confidence: 0.94 },
  action: 'approved',
  reason: 'All criteria met',
};

describe('Sequence Number', () => {
  describe('via Tzun SDK', () => {
    it('first capture gets sequenceNumber 1', async () => {
      const tzun = await Tzun.init();
      const result = await tzun.capture(captureInput);
      expect(result.stored).toBe(true);
      expect(result.envelope.payload.sequenceNumber).toBe(1);
    });

    it('subsequent captures increment monotonically', async () => {
      const tzun = await Tzun.init();
      const r1 = await tzun.capture(captureInput);
      const r2 = await tzun.capture({ ...captureInput, reason: 'Second' });
      const r3 = await tzun.capture({ ...captureInput, reason: 'Third' });

      expect(r1.envelope.payload.sequenceNumber).toBe(1);
      expect(r2.envelope.payload.sequenceNumber).toBe(2);
      expect(r3.envelope.payload.sequenceNumber).toBe(3);
    });

    it('sequenceNumber affects digest (same inputs produce different digests)', async () => {
      const tzun = await Tzun.init();
      const r1 = await tzun.capture(captureInput);
      const r2 = await tzun.capture(captureInput);

      // Even with identical inputs, different sequence numbers yield different digests
      expect(r1.envelope.integrity.canonicalDigest).not.toBe(
        r2.envelope.integrity.canonicalDigest
      );
      expect(r1.envelope.payload.sequenceNumber).toBe(1);
      expect(r2.envelope.payload.sequenceNumber).toBe(2);
    });

    it('failed capture does not advance sequence', async () => {
      const tzun = await Tzun.init();

      // First successful capture
      const r1 = await tzun.capture(captureInput);
      expect(r1.envelope.payload.sequenceNumber).toBe(1);

      // Failed capture (empty required fields)
      const rFail = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: {},
        action: '',
        reason: '',
      });
      expect(rFail.stored).toBe(false);

      // Next successful capture should still be 2, not 3
      const r2 = await tzun.capture(captureInput);
      expect(r2.envelope.payload.sequenceNumber).toBe(2);
    });
  });

  describe('sequence restores from storage', () => {
    it('writes last sequence into memory storage adapter', async () => {
      // First instance: capture 3 records
      const tzun1 = await Tzun.init();
      await tzun1.capture(captureInput);
      await tzun1.capture({ ...captureInput, reason: 'Second' });
      await tzun1.capture({ ...captureInput, reason: 'Third' });

      // Verify last sequence in storage
      const storage = tzun1.getStorage() as MemoryStorageAdapter;
      expect(await storage.getLastSequence()).toBe(3);
    });

    it('restores from SQLite adapter', async () => {
      const dbPath = path.join(
        os.tmpdir(),
        `tzun-test-seq-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`
      );

      let tzun1: Awaited<ReturnType<typeof Tzun.init>> | null = null;
      let tzun2: Awaited<ReturnType<typeof Tzun.init>> | null = null;
      try {
        // First instance: capture 2 records, then close. Closing flushes the
        // SQLite WAL so the next opener of the same file sees committed state.
        // Without close(), CI runs fail intermittently with "undefined" reads
        // because WAL contents aren't guaranteed to be visible across handles.
        // `mode: 'dev'`, not `'local'`. Storage is chosen by `dbPath`; mode
        // chooses ATTESTATION, and a production mode obtains an RFC 3161
        // timestamp for every record — a live round trip to freetsa.org on
        // every capture(), which this test does not need and the suite-wide guard
        // (tests/ts/setup/no-live-network.ts) refuses. Under `local` this file
        // made three TSA calls per run and failed as "Expected: 3, Received:
        // undefined" whenever one of them did. Sequence restore is a storage
        // property; the mode does not change it.
        tzun1 = await Tzun.init({ mode: 'dev', dbPath });
        await tzun1.capture(captureInput);
        await tzun1.capture({ ...captureInput, reason: 'Second' });
        await tzun1.close();
        tzun1 = null;

        // Second instance with same DB: should restore sequence to 3.
        tzun2 = await Tzun.init({ mode: 'dev', dbPath });
        const r3 = await tzun2.capture({ ...captureInput, reason: 'Third' });
        expect(r3.envelope.payload.sequenceNumber).toBe(3);
      } finally {
        if (tzun1) { try { await tzun1.close(); } catch { /* ignore */ } }
        if (tzun2) { try { await tzun2.close(); } catch { /* ignore */ } }
        try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
        try { fs.unlinkSync(dbPath + '-wal'); } catch { /* ignore */ }
        try { fs.unlinkSync(dbPath + '-shm'); } catch { /* ignore */ }
      }
    });
  });
});
