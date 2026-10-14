// Pins an explicit product decision: the SDK's tamper scanner covers ALL
// chains in the store, sealed ones included.
//
// `recovery.fork()` seals the old chain and restarts the new one at sequence 1,
// so a forked store holds two records numbered 1. The scanner walks every
// chain without raising false tamper on that, and the SDK leaves its own
// scanner unscoped rather than scoping it to the active chain. The reasoning
// is written out at `src/sdk/index.ts` where the scope would go. This file is
// the executable half of that comment.
//
// WHAT THE OTHER FORK TESTS DO NOT COVER
//
// `tests/ts/post-fork-scanning.test.ts` and the fork block in
// `tests/ts/scheduled-scanner.test.ts` both fork a store INSIDE the lifetime of
// one `Tzun.init()`. In that shape the chain that `Tzun.init()` saw as active
// is 'default' — the chain the fork later SEALS. So adding
// `tzun.scanner.setChainScope(activeChainId)` to `Tzun.init()` pins the scanner
// to the chain that ends up sealed, and
// `post-fork-scanning.test.ts` › 'the SEALED chain is still scanned' STILL
// PASSES. Verified, not assumed: with that line added, that test is green
// and it is the ACTIVE-chain tests that go red instead.
//
// The uncovered shape is the ordinary one for a deployed integrator: the
// process restarts. `Tzun.init()` then opens a store that ALREADY holds a fork,
// `getActiveChainId()` returns the NEW chain, and an init-time scope would
// silence the sealed chain — permanently, for every pass from then on, with no
// false alarm and no error to notice. That is the failure this file catches,
// and it needs storage that survives a restart, hence sqlite over a temp file
// rather than the in-memory adapter.
import Database from 'better-sqlite3';
import { withSqliteEnvelopeTriggersLifted } from './helpers/tamper-store';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Tzun } from '../../src/sdk/index';
import { EvidenceEnvelope, TamperIncident } from '@tzun/engine';

const scannerConfig = {
  batchSize: 100,
  workers: 2,
  mode: 'interval' as const,
  intervalMs: 0,
  verifyAttestation: false,
  verifyChainCompleteness: true,
};

function tmpDbPath(label: string): string {
  return path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-sealed-scope-')),
    `${label}.db`,
  );
}

function cleanup(dbPath: string): void {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
  }
  try { fs.rmdirSync(path.dirname(dbPath)); } catch { /* ignore */ }
}

/**
 * Open the SDK the way an integrator does — nothing hand-constructed.
 *
 * `mode: 'dev'`, not `'local'`. Storage is chosen by `dbPath`; mode
 * chooses ATTESTATION, and a production mode obtains an RFC 3161 timestamp
 * for every record — a live round trip to freetsa.org on
 * every capture(), six per run here, which the suite-wide guard
 * (tests/ts/setup/no-live-network.ts) refuses. Scanner coverage of a sealed
 * chain is a storage/scan property (`verifyAttestation: false` above); the
 * mode does not change what the scanner walks.
 */
function boot(dbPath: string): Promise<Tzun> {
  return Tzun.init({
    mode: 'dev',
    dbPath,
    verifyReads: false,
    monitoring: { enabled: true, scanner: scannerConfig },
  });
}

/**
 * Rewrite a payload field on a stored envelope without touching its stored
 * digest — the `digest_mismatch` shape. Done against the closed database file
 * so it models an edit made outside the SDK, which is what tampering is.
 */
function tamperPayloadOnDisk(dbPath: string, evidenceId: string): void {
  const db = new Database(dbPath);
  try {
    const row = db
      .prepare('SELECT envelope FROM envelopes WHERE evidence_id = ?')
      .get(evidenceId) as { envelope: string } | undefined;
    if (!row) throw new Error(`no envelope row for ${evidenceId}`);
    const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
    envelope.payload.reason = 'rewritten after the chain was sealed';
    withSqliteEnvelopeTriggersLifted(db, () =>
      db.prepare('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?')
        .run(JSON.stringify(envelope), evidenceId),
    );
  } finally {
    db.close();
  }
}

describe("Tzun.init()'s own scanner covers sealed chains", () => {
  it('catches tampering on the SEALED chain after the process restarts on a forked store', async () => {
    const dbPath = tmpDbPath('restart-sealed');
    let sealedChainId: string;
    let sealedEvidenceId: string;

    // --- Session 1: capture, fork, capture again, shut down. -----------------
    const first = await boot(dbPath);
    try {
      for (let i = 1; i <= 3; i++) {
        await first.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { old: i },
          action: 'approved',
          reason: `old-${i}`,
        });
      }
      sealedChainId = await first.getActiveChainId();
      await first.recovery.fork('inc-sealed-scope', {
        authorizedBy: 'admin@acme.example',
        reason: 'Signing key compromised; rotating the chain',
        forkAfterSequence: 1,
      });
      for (let i = 1; i <= 2; i++) {
        await first.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { fresh: i },
          action: 'approved',
          reason: `new-${i}`,
        });
      }

      const sealed = await first.getStorage().listBySequence(1, 10, sealedChainId);
      expect(sealed).toHaveLength(3);
      sealedEvidenceId = sealed[2].payload.evidenceId;
    } finally {
      await first.close();
    }

    // --- The tamper: an edit to the sealed chain, made with the SDK down. ----
    tamperPayloadOnDisk(dbPath, sealedEvidenceId);

    // --- Session 2: a plain restart. ----------------------------------------
    const second = await boot(dbPath);
    try {
      // Non-vacuity guard for the assertion below. On this restart the chain
      // `Tzun.init()` resolves as active is the POST-fork chain, so scoping the
      // SDK's scanner to it would exclude the chain we just tampered. If this
      // ever stops holding, the test below has stopped proving anything and the
      // scenario needs rebuilding — it is not enough for it to stay green.
      const activeChainId = await second.getActiveChainId();
      expect(activeChainId).not.toBe(sealedChainId);
      const sealedIsNotActive = await second
        .getStorage()
        .listBySequence(1, 10, sealedChainId);
      expect(sealedIsNotActive).toHaveLength(3);

      await second.runScan();

      // The point of the whole file: the scanner the SDK handed us reached a
      // chain nobody is writing to any more, and found the edit.
      const incidents = await second.getStorage().listIncidents();
      const mismatches = incidents.filter(
        (i: TamperIncident) => i.type === 'digest_mismatch',
      );
      expect(mismatches).toHaveLength(1);
      expect(mismatches[0].affectedRecords).toEqual([sealedEvidenceId]);
    } finally {
      await second.close();
      cleanup(dbPath);
    }
  }, 30_000);

  it('leaves the restarted scanner unscoped, and still raises nothing on a clean forked store', async () => {
    const dbPath = tmpDbPath('restart-clean');
    const first = await boot(dbPath);
    try {
      // `capture()` never throws — a refused append comes back as
      // `{ stored: false, failure }` — so every capture is checked here. Without
      // this the count below cannot tell "the scanner skipped a record" from
      // "a record was never written".
      for (let i = 1; i <= 3; i++) {
        const r = await first.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { old: i },
          action: 'approved',
          reason: `old-${i}`,
        });
        expect({ capture: `old-${i}`, stored: r.stored, failure: r.failure }).toEqual({ capture: `old-${i}`, stored: true, failure: undefined });
      }
      await first.recovery.fork('inc-sealed-scope-2', {
        authorizedBy: 'admin@acme.example',
        reason: 'Rotating the chain',
        forkAfterSequence: 1,
      });
      for (let i = 1; i <= 2; i++) {
        const r = await first.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { fresh: i },
          action: 'approved',
          reason: `new-${i}`,
        });
        expect({ capture: `new-${i}`, stored: r.stored, failure: r.failure }).toEqual({ capture: `new-${i}`, stored: true, failure: undefined });
      }
    } finally {
      await first.close();
    }

    const second = await boot(dbPath);
    const summaries: Array<{ recordsChecked: number }> = [];
    second.on('scan.completed', (s) => summaries.push(s));
    try {
      await second.runScan();
      await new Promise((r) => setTimeout(r, 50));

      // FIVE: 3 on the sealed chain plus 2 on the live one. Two would mean the
      // sealed chain fell out of the rotation; three would mean the live one did.
      // Asserted BEFORE the scope field below, deliberately: the behaviour is
      // what is being pinned, and a failure should say "the pass stopped
      // covering records", not "a field is set".
      expect(summaries).toHaveLength(1);
      if (summaries[0].recordsChecked !== 5) {
        // Say WHICH chain the pass under-counted, and what the store holds.
        const storage = second.getStorage();
        const chains = await storage.listChains();
        const dump = {
          recordsChecked: summaries[0].recordsChecked,
          summary: summaries[0],
          activeChainId: await storage.getActiveChainId(),
          lastSequence: await storage.getLastSequence(),
          chains: await Promise.all(chains.map(async (c) => ({
            chain: c,
            forks: await storage.listForksForChain(c.chainId),
            records: (await storage.listBySequence(undefined, undefined, c.chainId)).map((e) => ({
              seq: e.payload.sequenceNumber,
              evidenceId: e.payload.evidenceId,
              custody: e.custodyChain.map((x) => x.action),
            })),
          }))),
          unscopedRecords: (await storage.listBySequence()).map((e) => e.payload.sequenceNumber),
          incidents: await storage.listIncidents(),
        };
        throw new Error(`scan covered ${dump.recordsChecked} records, expected 5:\n${JSON.stringify(dump, null, 2)}`);
      }
      expect(summaries[0].recordsChecked).toBe(5);
      // And walking both chains still invents nothing on an untouched store:
      // the two records numbered 1 across the fork raise no false tamper.
      expect(await second.getStorage().listIncidents()).toEqual([]);

      // The default the SDK ships: no scope. Cheap, and it names the field, but
      // it is the count above and the tamper test before it that carry the
      // weight — a scope re-applied elsewhere could leave this field unset.
      const scanner = (second as unknown as {
        scanner: { getChainScope(): string | undefined };
      }).scanner;
      expect(scanner.getChainScope()).toBeUndefined();
    } finally {
      await second.close();
      cleanup(dbPath);
    }
  }, 30_000);
});
