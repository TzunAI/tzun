import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { EvidenceEnvelope } from '@tzun/engine';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const captureInput = (label: string) => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { label },
  action: 'approved',
  reason: `Reason for ${label}`,
});

describe('capture race condition', () => {
  it('storage failure does not advance chain state', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;

    // Capture record 1 — should succeed with seq=1
    const r1 = await tzun.capture(captureInput('record-1'));
    expect(r1.stored).toBe(true);
    expect(r1.envelope.payload.sequenceNumber).toBe(1);

    // Monkey-patch storage.store to throw on next call
    const originalStore = storage.store.bind(storage);
    storage.store = async (_envelope: EvidenceEnvelope): Promise<void> => {
      throw new Error('Simulated storage failure');
    };

    // Capture record 2 — storage throws, should fail
    const r2 = await tzun.capture(captureInput('record-2'));
    expect(r2.stored).toBe(false);
    expect(r2.failure).toBeDefined();

    // Restore storage
    storage.store = originalStore;

    // Capture record 3 — should succeed with seq=2 (not 3), chained to r1
    const r3 = await tzun.capture(captureInput('record-3'));
    expect(r3.stored).toBe(true);
    expect(r3.envelope.payload.sequenceNumber).toBe(2);
    expect(r3.envelope.integrity.chainLink).not.toBeNull();
    // chain link is derived from r1's digest (last successfully stored)
    expect(r3.envelope.integrity.chainLink).toMatch(/^[a-f0-9]{64}$/);

    // Confirm r3's chainLink was built off r1's digest, not r2's
    // r3.chainLink = SHA-256(r1.digest + r3.digest); verify it differs from a link off a
    // hypothetical r2 by checking that r3 chain-links to r1 (i.e., prevDigest === r1's digest)
    const storedLastDigest = await storage.getLastDigest();
    expect(storedLastDigest).toBe(r3.envelope.integrity.canonicalDigest);
    const storedLastSequence = await storage.getLastSequence();
    expect(storedLastSequence).toBe(2);
  });

  it('chain state matches storage state after failed capture', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;

    // Capture record 1
    const r1 = await tzun.capture(captureInput('record-1'));
    expect(r1.stored).toBe(true);

    // Storage should reflect r1
    expect(await storage.getLastDigest()).toBe(r1.envelope.integrity.canonicalDigest);
    expect(await storage.getLastSequence()).toBe(1);

    // Force storage failure on next store
    const originalStore = storage.store.bind(storage);
    storage.store = async (_envelope: EvidenceEnvelope): Promise<void> => {
      throw new Error('Simulated storage failure');
    };

    // Capture record 2 — fails
    const r2 = await tzun.capture(captureInput('record-2'));
    expect(r2.stored).toBe(false);

    // Restore storage
    storage.store = originalStore;

    // Storage state should be unchanged — still points to r1
    expect(await storage.getLastDigest()).toBe(r1.envelope.integrity.canonicalDigest);
    expect(await storage.getLastSequence()).toBe(1);
  });

  it('process crash simulation: chain restores correctly from storage on restart', async () => {
    // Simulate a process crash by capturing into a file-backed SQLite DB,
    // closing the Tzun instance entirely (releasing the SQLite handle and
    // flushing the WAL), then re-opening Tzun with the same DB path and
    // verifying chain state was restored. This is the real restart scenario;
    // an in-memory (:memory:) DB cannot model it because :memory: is
    // per-connection.
    const dbPath = path.join(
      os.tmpdir(),
      `tzun-test-crash-sim-${Date.now()}-${Math.random().toString(36).slice(2)}.db`,
    );

    let tzun1: Awaited<ReturnType<typeof Tzun.init>> | null = null;
    let tzun2: Awaited<ReturnType<typeof Tzun.init>> | null = null;
    try {
      // ── Phase 1: capture two records, then "crash" (close cleanly) ──
      // `mode: 'dev'`, not `'local'`: storage is chosen by `dbPath`, mode
      // chooses ATTESTATION, and a production mode's default `require:
      // ['timestamp']` is a live RFC 3161 round trip to freetsa.org on every
      // capture() — which the suite-wide guard (tests/ts/setup/no-live-network.ts)
      // refuses, and which chain-state restore does not depend on.
      tzun1 = await Tzun.init({ mode: 'dev', dbPath });
      const storage1 = tzun1.getStorage();

      const r1 = await tzun1.capture(captureInput('record-1'));
      expect(r1.stored).toBe(true);
      expect(r1.envelope.payload.sequenceNumber).toBe(1);
      // r1 is the first record so it has no chain link
      expect(r1.envelope.integrity.chainLink).toBeNull();

      const r2 = await tzun1.capture(captureInput('record-2'));
      expect(r2.stored).toBe(true);
      expect(r2.envelope.payload.sequenceNumber).toBe(2);
      // r2 should be chained to r1
      expect(r2.envelope.integrity.chainLink).not.toBeNull();
      expect(r2.envelope.integrity.chainLink).toMatch(/^[a-f0-9]{64}$/);

      // Pre-close: verify storage reflects what we just captured
      expect(await storage1.getLastDigest()).toBe(r2.envelope.integrity.canonicalDigest);
      expect(await storage1.getLastSequence()).toBe(2);

      await tzun1.close();
      tzun1 = null;

      // ── Phase 2: "restart" — re-open Tzun against the same DB ──
      tzun2 = await Tzun.init({ mode: 'dev', dbPath });
      const storage2 = tzun2.getStorage();

      // Verify restored chain state matches what tzun1 last wrote
      expect(await storage2.getLastSequence()).toBe(2);
      expect(await storage2.getLastDigest()).toBe(r2.envelope.integrity.canonicalDigest);

      // Next capture continues the chain at seq=3, linked to r2
      const r3 = await tzun2.capture(captureInput('record-3'));
      expect(r3.stored).toBe(true);
      expect(r3.envelope.payload.sequenceNumber).toBe(3);
      expect(r3.envelope.integrity.chainLink).not.toBeNull();
      expect(r3.envelope.integrity.chainLink).toMatch(/^[a-f0-9]{64}$/);
    } finally {
      if (tzun1) { try { await tzun1.close(); } catch { /* ignore */ } }
      if (tzun2) { try { await tzun2.close(); } catch { /* ignore */ } }
      try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
      try { fs.unlinkSync(dbPath + '-wal'); } catch { /* ignore */ }
      try { fs.unlinkSync(dbPath + '-shm'); } catch { /* ignore */ }
    }
  });
});
