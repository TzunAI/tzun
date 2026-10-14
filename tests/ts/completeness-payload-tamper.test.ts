// `verifyChainCompleteness()` must catch the cheapest attack on an evidence
// store: rewriting a record's payload and leaving `integrity.canonicalDigest`
// at the value it already held.
//
// The walk's structural checks — sequence continuity, duplicate/backwards
// sequence numbers, and `chainLink == SHA-256(prevDigest ‖ curDigest)` — are
// all computed over DIGESTS. A naive payload rewrite leaves every digest stale
// rather than recomputed, so every link still agrees and no sequence number
// moves: those three checks alone would report `valid: true` on a chain
// holding a forged record. The walk also recomputes each record's digest and
// reports the records that do not hash to their stored digest in
// `digestMismatches`.
//
// The other three attacks all require the attacker to ADD or REMOVE a row. The
// payload rewrite requires neither, so the digest check is the only one that
// catches it.
//
// Coverage note on adapters. The memory-adapter cases below tamper by rewriting
// the row the store holds, through `rewriteStoredEnvelope`; assigning to the
// object `retrieve()` returned would not reach the store, because the memory
// adapter clones on every read and write, like a real store. The SQLite cases
// tamper with `UPDATE envelopes SET envelope = ?` against the CLOSED database
// file, with the SDK down — an edit made outside the SDK, which is what
// tampering is — and then reopen. They are the cases that prove the check
// survives a real serialize/parse round-trip, and the clean-chain SQLite case
// is the one that would fail if the round-trip were not byte-faithful.
//
// The SQLite cases run in `mode: 'dev'`, not `mode: 'local'`. Storage is chosen
// by `dbPath`; mode chooses ATTESTATION, and a production mode obtains an RFC
// 3161 timestamp for every record (src/sdk/mode-resolver.ts), which is a live
// round trip to https://freetsa.org/tsr on every capture() and cannot be turned
// off in `local` (`validateAttestationConfig` refuses `require: []`). Under
// `local`, with the timestamp required, every capture in this file would make
// a TSA call and the run would fail whenever one of them did: the orchestrator
// drops a component failure silently when no `onLog` sink is configured
// (src/attestation/orchestrator.ts), the SDK turns the missing token into
// `{ stored: false, failure: attestation_failure }`, and the database left
// behind holds `Required attestation service(s) failed: timestamp`.
// Payload-tamper detection on a real file has no attestation dependency.
// `fetch` is stubbed for the whole file so a switch to `local` fails
// deterministically, with the failure record in the diff.
import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { rewriteStoredEnvelope, withSqliteEnvelopeTriggersLifted } from './helpers/tamper-store';
import { verifyChainCompleteness } from '@tzun/engine';
import { EvidenceEnvelope } from '@tzun/engine';

const captureInput = (label: string) => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { label },
  action: 'approved',
  reason: `Reason for ${label}`,
});

async function captureRecords(tzun: Tzun, count: number): Promise<EvidenceEnvelope[]> {
  const envelopes: EvidenceEnvelope[] = [];
  for (let i = 1; i <= count; i++) {
    const result = await tzun.capture(captureInput(`record-${i}`));
    // The failure record first: on its own, `stored` fails as "Expected: true,
    // Received: false" and says nothing about WHY the SDK refused.
    expect(result.failure).toBeUndefined();
    expect(result.stored).toBe(true);
    envelopes.push(result.envelope);
  }
  return envelopes;
}

function tmpDbPath(label: string): string {
  return path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-completeness-tamper-')),
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
 * Rewrite one payload field on a stored envelope and leave the stored digest
 * alone — the `digest_mismatch` shape, applied to the closed database file.
 */
function tamperPayloadOnDisk(dbPath: string, evidenceId: string): void {
  const db = new Database(dbPath);
  try {
    const row = db
      .prepare('SELECT envelope FROM envelopes WHERE evidence_id = ?')
      .get(evidenceId) as { envelope: string } | undefined;
    if (!row) throw new Error(`no envelope row for ${evidenceId}`);
    const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
    envelope.payload.reason = 'TAMPERED — the approver never wrote this';
    withSqliteEnvelopeTriggersLifted(db, () =>
      db.prepare('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?')
        .run(JSON.stringify(envelope), evidenceId),
    );
  } finally {
    db.close();
  }
}

// No network in this file — see the header. A capture that reaches for a TSA
// fails here the way it fails during an outage, and does so on every run.
const realFetch = globalThis.fetch;
beforeAll(() => {
  globalThis.fetch = (async (input: unknown) => {
    throw new Error(
      `completeness-payload-tamper.test.ts must not reach the network (fetch ${String(input)}); ` +
        "init in mode: 'dev' so no attestation service is required.",
    );
  }) as typeof fetch;
});
afterAll(() => {
  globalThis.fetch = realFetch;
});

describe('verifyChainCompleteness — payload tampering (memory adapter)', () => {
  it('reports a rewritten HEAD payload with a stale digest as invalid', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 7);

    const victim = envelopes[6];
    await rewriteStoredEnvelope(storage, victim.payload.evidenceId, (e) => {
      e.payload.reason = 'TAMPERED — the approver never wrote this';
    });

    const result = await verifyChainCompleteness(storage);

    expect(result.digestMismatches).toEqual([victim.payload.evidenceId]);
    expect(result.valid).toBe(false);
    // The three structural checks stay silent, which is the whole point: this
    // attack is invisible to every one of them, so only the digest check can
    // be what flipped `valid`.
    expect(result.sequenceGaps).toEqual([]);
    expect(result.duplicateSequences).toEqual([]);
    expect(result.brokenLinks).toEqual([]);
    expect(result.totalRecords).toBe(7);
  });

  it('reports a rewritten MID-CHAIN payload with a stale digest as invalid', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 7);

    const victim = envelopes[2];
    await rewriteStoredEnvelope(storage, victim.payload.evidenceId, (e) => {
      e.payload.aiOutput = { label: 'a recommendation the model never made' };
    });

    const result = await verifyChainCompleteness(storage);

    expect(result.digestMismatches).toEqual([victim.payload.evidenceId]);
    expect(result.valid).toBe(false);
    expect(result.brokenLinks).toEqual([]);
  });

  it('reports every rewritten record, not just the first', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 5);

    for (const index of [1, 3]) {
      await rewriteStoredEnvelope(storage, envelopes[index].payload.evidenceId, (e) => {
        e.payload.reason = 'TAMPERED';
      });
    }

    const result = await verifyChainCompleteness(storage);

    expect(result.digestMismatches).toEqual([
      envelopes[1].payload.evidenceId,
      envelopes[3].payload.evidenceId,
    ]);
    expect(result.valid).toBe(false);
  });

  it('an unknown schemaVersion is reported, because it is not in the hashed field set', async () => {
    // schemaVersion is NOT covered by canonicalDigest, so an attacker with
    // store-write access can set it to anything for free. Treating an
    // unrecognised version as "unverifiable, therefore silent" would reopen
    // the silence the digest check closes: rewrite the payload, then set
    // schemaVersion to 'v9.9' and the digest check has no rules to run.
    // `VerifyingStorageProxy.quickVerify` takes the same position.
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 3);

    const victim = envelopes[1];
    await rewriteStoredEnvelope(storage, victim.payload.evidenceId, (e) => {
      e.payload.reason = 'TAMPERED';
      e.payload.schemaVersion = 'v9.9';
    });

    const result = await verifyChainCompleteness(storage);

    expect(result.digestMismatches).toEqual([victim.payload.evidenceId]);
    expect(result.valid).toBe(false);
  });

  it('a clean chain reports no digest mismatches', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    await captureRecords(tzun, 5);

    const result = await verifyChainCompleteness(storage);

    expect(result.digestMismatches).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it('an empty chain reports no digest mismatches', async () => {
    const tzun = await Tzun.init();
    const result = await verifyChainCompleteness(tzun.getStorage());

    expect(result.digestMismatches).toEqual([]);
    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(0);
  });
});

describe('Tzun.verifyChainCompleteness() — payload tampering (sqlite, tampered on disk)', () => {
  it('reports a payload rewritten in the database file while the SDK was down', async () => {
    const dbPath = tmpDbPath('payload-tamper');
    let victimId: string;

    const first = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const envelopes = await captureRecords(first, 7);
      victimId = envelopes[6].payload.evidenceId;
      // Baseline: the same store, same method, before the edit.
      const clean = await first.verifyChainCompleteness();
      expect(clean.valid).toBe(true);
      expect(clean.digestMismatches).toEqual([]);
      expect(clean.totalRecords).toBe(7);
    } finally {
      await first.close();
    }

    tamperPayloadOnDisk(dbPath, victimId!);

    const second = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const result = await second.verifyChainCompleteness();

      expect(result.digestMismatches).toEqual([victimId!]);
      expect(result.valid).toBe(false);
      expect(result.sequenceGaps).toEqual([]);
      expect(result.duplicateSequences).toEqual([]);
      expect(result.brokenLinks).toEqual([]);
      expect(result.totalRecords).toBe(7);
    } finally {
      await second.close();
      cleanup(dbPath);
    }
  });

  it('verifyAllChains() goes invalid when the SEALED chain carries the rewritten payload', async () => {
    // A sealed chain is the read-only remainder of a fork and is exactly where
    // an insider would tamper: nothing appends to it again, so nothing else
    // would notice.
    const dbPath = tmpDbPath('sealed-payload-tamper');
    let sealedChainId: string;
    let victimId: string;

    const first = await Tzun.init({ mode: 'dev', dbPath });
    try {
      await captureRecords(first, 3);
      sealedChainId = await first.getActiveChainId();
      await first.recovery.fork('inc-payload-tamper', {
        authorizedBy: 'admin@acme.example',
        reason: 'Signing key compromised; rotating the chain',
        forkAfterSequence: 1,
      });
      await captureRecords(first, 2);

      const sealed = await first.getStorage().listBySequence(1, 10, sealedChainId);
      expect(sealed).toHaveLength(3);
      victimId = sealed[2].payload.evidenceId;
    } finally {
      await first.close();
    }

    tamperPayloadOnDisk(dbPath, victimId!);

    const second = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const report = await second.verifyAllChains();

      // The ACTIVE chain is untouched, and its own result still says so.
      expect(report.active.valid).toBe(true);
      expect(report.active.digestMismatches).toEqual([]);

      // The store as a whole is not clean.
      expect(report.valid).toBe(false);
      const sealedResult = report.chains.find((c) => c.chainId === sealedChainId!)!;
      expect(sealedResult.digestMismatches).toEqual([victimId!]);
      expect(sealedResult.valid).toBe(false);
    } finally {
      await second.close();
      cleanup(dbPath);
    }
  });
});
