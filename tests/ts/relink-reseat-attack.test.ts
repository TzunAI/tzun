// relink() must not launder a rewrite-and-reseat tamper as an honest link
// repair, and the store's present state alone cannot tell the two apart.
//
// THE ATTACK. Rewrite record N's payload, RECOMPUTE its canonicalDigest, and
// REPAIR its own chainLink to H(digest(N-1) ‖ digest'(N)). Now exactly one
// link in the chain is inconsistent: N+1's, which still names the old
// digest(N).
//
// WHY BOTH relink() GUARDS MISS IT. Guard 1 refuses a record that does not
// hash to its stored digest — N does. Guard 2 refuses a record whose link AND
// whose successor's link are both inconsistent — only N+1's is. What is left
// is indistinguishable, from the store's present state, from one honestly
// corrupted link, which is the case relink() exists to repair.
//
// WHAT LAUNDERING WOULD LOOK LIKE: relink() performs the repair, returns
// chainVerified: true, and writes operator-signed 'relinked' custody entries
// stating the chain was correctly repaired. The rewritten payload then sits
// inside a chain that scans clean, with a signed audit trail vouching for it.
//
// THE DEFENCE. The present links and digests do not remember N's prior
// digest, so from them alone "N was rewritten and reseated" and "N+1's link
// got corrupted" are the same observation. The append-only revision log is
// that memory:
// `store()` writes the capture digest as revision 0, and a record whose
// current digest is not that one was rewritten after capture, however
// consistent its links now look. `verifyChainCompleteness()` reports it as
// `digestSuperseded` and `relink()` refuses over it.
//
// THIS FILE. The first test pins the attack's signature against the checks
// that read only the store's PRESENT state: one broken link, no digest
// mismatch — proof the setup is the attack described above and that nothing
// computed from present state can see it. The second asserts the defence:
// relink() refuses, naming both digests, and no custody entry vouches for the
// forged record. The third asserts that relink() does not launder the reseat
// or sign off on it: nothing repaired, no relink record, no custody entry,
// and a chain that still scans dirty afterwards, with the forged record named
// in `digestSuperseded`.
//
// The discrimination is the whole point, so the fourth test proves the other
// side of it: an HONEST single-link corruption — same one-broken-link
// signature, payload untouched — still relinks cleanly. A defence that
// refused both would not be a defence, it would be the removal of relink().
//
// Runs on the SQLite adapter. The reseat is applied to the CLOSED database
// file through better-sqlite3 — an edit made outside the SDK — so the digest,
// link and payload all go through a real serialize/parse round-trip.
import Database from 'better-sqlite3';
import { withSqliteEnvelopeTriggersLifted } from './helpers/tamper-store';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Tzun } from '../../src/sdk/index';
import {
  EvidenceChain,
  EvidenceEnvelope,
  SchemaRegistry,
  TamperIncident,
  canonicalSerialize,
  computeDigest,
} from '@tzun/engine';

const FORGED_REASON = 'Approved — the approver never wrote this';

function tmpDbPath(label: string): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-')), `${label}.db`);
}

function cleanup(dbPath: string): void {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
  }
  try { fs.rmdirSync(path.dirname(dbPath)); } catch { /* ignore */ }
}

function boot(dbPath: string): Promise<Tzun> {
  return Tzun.init({ dbPath });
}

/**
 * The reseat: rewrite the payload, recompute the digest over the schema's
 * hashed field set exactly as the SDK does, and repair the record's own link
 * onto its predecessor's (untouched) digest.
 */
function rewriteAndReseatOnDisk(
  dbPath: string,
  evidenceId: string,
  predecessorDigest: string,
): { oldDigest: string; newDigest: string } {
  const db = new Database(dbPath);
  try {
    const row = db
      .prepare('SELECT envelope FROM envelopes WHERE evidence_id = ?')
      .get(evidenceId) as { envelope: string } | undefined;
    if (!row) throw new Error(`no envelope row for ${evidenceId}`);
    const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
    const oldDigest = envelope.integrity.canonicalDigest;

    envelope.payload.reason = FORGED_REASON;
    const schema = new SchemaRegistry().get(envelope.payload.schemaVersion)!;
    const newDigest = computeDigest(
      canonicalSerialize(envelope.payload as unknown as Record<string, unknown>, schema.hashedFieldSet),
    );
    envelope.integrity.canonicalDigest = newDigest;
    const chain = new EvidenceChain();
    chain.restore(predecessorDigest);
    envelope.integrity.chainLink = chain.computeLink(newDigest);

    withSqliteEnvelopeTriggersLifted(db, () =>
      db.prepare('UPDATE envelopes SET envelope = ?, digest = ? WHERE evidence_id = ?')
        .run(JSON.stringify(envelope), newDigest, evidenceId),
    );
    return { oldDigest, newDigest };
  } finally {
    db.close();
  }
}

/**
 * An HONEST corruption: overwrite one record's chainLink and touch nothing
 * else. Same one-broken-link signature as the reseat, but every payload still
 * hashes to the digest it was captured with.
 */
function corruptChainLinkOnDisk(dbPath: string, evidenceId: string): void {
  const db = new Database(dbPath);
  try {
    const row = db
      .prepare('SELECT envelope FROM envelopes WHERE evidence_id = ?')
      .get(evidenceId) as { envelope: string } | undefined;
    if (!row) throw new Error(`no envelope row for ${evidenceId}`);
    const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
    envelope.integrity.chainLink = 'c'.repeat(64);
    db.prepare('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?')
      .run(JSON.stringify(envelope), evidenceId);
  } finally {
    db.close();
  }
}

function chainBreakIncident(evidenceId: string): TamperIncident {
  return {
    id: 'inc-reseat',
    detectedAt: new Date().toISOString(),
    severity: 'critical',
    type: 'chain_break',
    affectedRecords: [evidenceId],
    details: 'Chain break detected during scan.',
    status: 'open',
  };
}

interface Fixture {
  /** The five captured envelopes, index 0 = sequence 1. */
  captured: EvidenceEnvelope[];
  victimId: string;
  successorId: string;
  oldDigest: string;
  newDigest: string;
}

/** Five records; record 3 rewritten and reseated onto record 2. */
async function reseatedStore(dbPath: string): Promise<Fixture> {
  const tzun = await boot(dbPath);
  const captured: EvidenceEnvelope[] = [];
  try {
    for (let i = 1; i <= 5; i++) {
      const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `record-${i}` });
      expect(result.failure).toBeUndefined();
      expect(result.stored).toBe(true);
      captured.push(result.envelope);
    }
  } finally {
    await tzun.close();
  }
  const victimId = captured[2].payload.evidenceId;
  const { oldDigest, newDigest } = rewriteAndReseatOnDisk(dbPath, victimId, captured[1].integrity.canonicalDigest);
  return { captured, victimId, successorId: captured[3].payload.evidenceId, oldDigest, newDigest };
}

describe('rewrite-and-reseat against relink() (SQLite)', () => {
  let dbPath: string;
  beforeEach(() => { dbPath = tmpDbPath('reseat'); });
  afterEach(() => cleanup(dbPath));

  it('the reseat leaves exactly one inconsistent link and no digest mismatch — the signature of an honest link corruption', async () => {
    const { victimId, successorId, oldDigest, newDigest } = await reseatedStore(dbPath);
    expect(newDigest).not.toBe(oldDigest);

    const tzun = await boot(dbPath);
    try {
      const victim = (await tzun.getStorage().retrieve(victimId))!;
      expect(victim.payload.reason).toBe(FORGED_REASON);
      expect(victim.integrity.canonicalDigest).toBe(newDigest);

      const result = await tzun.verifyChainCompleteness();
      expect(result.valid).toBe(false);
      // Every check that reads the store sees precisely what it would see for
      // one corrupted link on record 4 — and nothing else.
      expect(result.digestMismatches).toEqual([]);
      expect(result.brokenLinks).toEqual([successorId]);
      expect(result.sequenceGaps).toEqual([]);
      expect(result.duplicateSequences).toEqual([]);
      expect(result.totalRecords).toBe(5);
    } finally {
      await tzun.close();
    }
  });

  it('relink() refuses to re-link over a record that was rewritten and reseated', async () => {
    const { successorId, victimId, oldDigest, newDigest } = await reseatedStore(dbPath);

    const tzun = await boot(dbPath);
    try {
      await tzun.getStorage().storeIncident(chainBreakIncident(successorId));
      // The refusal names both digests, because "this record no longer hashes
      // to what it was captured with" is the finding, and an operator who is
      // being told to fork() instead is owed the evidence for it.
      await expect(
        tzun.recovery.relink('inc-reseat', { fromSequence: 4, authorizedBy: 'operator@acme.example' }),
      ).rejects.toThrow(
        new RegExp(`no longer hashes to the digest it was CAPTURED with[\\s\\S]*${oldDigest}[\\s\\S]*${newDigest}`),
      );

      // If it refused, nothing vouched for the forged record.
      const victim = (await tzun.getStorage().retrieve(victimId))!;
      const successor = (await tzun.getStorage().retrieve(successorId))!;
      for (const record of [victim, successor]) {
        expect(record.custodyChain.some((c) => c.action === 'relinked')).toBe(false);
      }
    } finally {
      await tzun.close();
    }
  });

  // A laundered reseat would mean: relink() performs the repair, returns
  // chainVerified: true, writes an operator-signed 'relinked' custody entry
  // naming the incident, and leaves the forged payload inside a chain that
  // scans clean (`valid: true, brokenLinks: [], digestMismatches: []`). That
  // is a signed audit trail vouching for a decision nobody made. Each
  // assertion below checks the negation of one of those outcomes.
  it('relink() does not launder the reseat: nothing repaired, nothing signed, the chain still reports it', async () => {
    const { captured, victimId, successorId, newDigest } = await reseatedStore(dbPath);

    const tzun = await boot(dbPath);
    try {
      await tzun.getStorage().storeIncident(chainBreakIncident(successorId));
      await expect(
        tzun.recovery.relink('inc-reseat', { fromSequence: 4, authorizedBy: 'operator@acme.example' }),
      ).rejects.toThrow(/Use fork\(\)/);

      // No repair: record 4's link does NOT agree with the forged digest.
      const expectedForgedLink = (() => {
        const chain = new EvidenceChain();
        chain.restore(newDigest);
        return chain.computeLink(captured[3].integrity.canonicalDigest);
      })();
      const successor = (await tzun.getStorage().retrieve(successorId))!;
      expect(successor.integrity.chainLink).not.toBe(expectedForgedLink);
      expect(successor.integrity.chainLink).toBe(captured[3].integrity.chainLink);

      // No operator-signed custody entry vouches for anything, on either
      // record — and no relink record was stored for the incident.
      const victim = (await tzun.getStorage().retrieve(victimId))!;
      for (const record of [victim, successor]) {
        expect(record.custodyChain.some((c) => c.action === 'relinked')).toBe(false);
      }
      expect(await tzun.getStorage().listRelinks('inc-reseat')).toEqual([]);

      // The forged payload is still there — relink() repairs links, it never
      // restores payloads — but the chain no longer scans clean over it, and
      // says WHY: superseded, not merely broken.
      expect(victim.payload.reason).toBe(FORGED_REASON);
      const after = await tzun.verifyChainCompleteness();
      expect(after).toMatchObject({
        valid: false,
        brokenLinks: [successorId],
        digestMismatches: [],
        digestSuperseded: [victimId],
        totalRecords: 5,
      });
    } finally {
      await tzun.close();
    }
  });

  // THE OTHER SIDE OF THE DISCRIMINATION. Same observable signature as the
  // attack — exactly one inconsistent link, no digest mismatch — but the
  // payload was never touched, so every record still hashes to the digest it
  // was captured with and relink() does its job. If this test went red the
  // "defence" would just be relink() refusing everything.
  it('an HONEST single-link corruption still re-links cleanly and is signed off', async () => {
    const tzun = await boot(dbPath);
    const captured: EvidenceEnvelope[] = [];
    try {
      for (let i = 1; i <= 5; i++) {
        const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `record-${i}` });
        captured.push(result.envelope);
      }
    } finally {
      await tzun.close();
    }

    // Corrupt ONE link on the closed file — the payload and every digest in
    // the store are untouched, which is the whole difference from the reseat.
    const victimId = captured[3].payload.evidenceId;
    corruptChainLinkOnDisk(dbPath, victimId);

    const tzun2 = await boot(dbPath);
    try {
      const before = await tzun2.verifyChainCompleteness();
      // Indistinguishable from the attack by present state alone.
      expect(before).toMatchObject({
        valid: false,
        brokenLinks: [victimId],
        digestMismatches: [],
        digestSuperseded: [],
      });

      await tzun2.getStorage().storeIncident(chainBreakIncident(victimId));
      const result = await tzun2.recovery.relink('inc-reseat', {
        fromSequence: 4,
        authorizedBy: 'operator@acme.example',
      });

      expect(result.chainVerified).toBe(true);
      expect(result.relink.modifiedLinks.map((l) => l.sequenceNumber)).toEqual([4]);
      expect(result.relink.modifiedLinks[0].newChainLink).toBe(captured[3].integrity.chainLink);

      const repaired = (await tzun2.getStorage().retrieve(victimId))!;
      const relinked = repaired.custodyChain.filter((c) => c.action === 'relinked');
      expect(relinked).toHaveLength(1);
      expect(relinked[0].actor).toBe('operator@acme.example');

      const after = await tzun2.verifyChainCompleteness();
      expect(after).toMatchObject({
        valid: true,
        brokenLinks: [],
        digestMismatches: [],
        digestSuperseded: [],
        totalRecords: 5,
      });

      // The repair is in the revision log, attributed to the operator, with
      // the digest carried forward unchanged from revision 0.
      const revisions = await tzun2.getStorage().listEnvelopeRevisions(victimId);
      expect(revisions.map((r) => r.cause)).toEqual(['capture', 'relink']);
      expect(revisions[1].actor).toBe('operator@acme.example');
      expect(revisions[1].canonicalDigest).toBe(revisions[0].canonicalDigest);
      expect(revisions[1].chainLink).toBe(captured[3].integrity.chainLink);
    } finally {
      await tzun2.close();
    }
  });
});
