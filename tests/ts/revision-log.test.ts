/**
 * The append-only revision log, on real adapters.
 *
 * WHAT IT IS FOR. Without this log, nothing in an evidence store remembers
 * what a record hashed to when it was captured, so "record N was rewritten
 * and its own link reseated" and "record N+1's link got corrupted" leave the
 * store in the SAME state and no check can tell them apart. `relink-reseat-attack.test.ts`
 * exercises the attack end to end; THIS file is about the mechanism it rests
 * on — the rows themselves, when they are written, what they say, and that
 * they cannot be removed.
 *
 * ADAPTERS. Every case runs on SQLite (a real file, opened and closed, so the
 * rows go through a serialize/parse round trip) and on memory, from the same
 * body — the two must agree or a test written against the double says nothing
 * about a real store. The DELETE/UPDATE refusal is SQLite-only because
 * it is a database trigger; the memory adapter's equivalent is the absence of
 * any method that could remove a row, which is asserted structurally.
 */
import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import {
  EvidenceEnvelope,
  SchemaRegistry,
  StorageAdapter,
  canonicalSerialize,
  computeDigest,
} from '@tzun/engine';

interface Leg {
  name: string;
  /** A live Tzun over the adapter under test, plus a teardown. */
  boot: () => Promise<{ tzun: Tzun; teardown: () => Promise<void> }>;
}

function tmpDbPath(label: string): { dbPath: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-rev-'));
  const dbPath = path.join(dir, `${label}.db`);
  return {
    dbPath,
    cleanup: () => {
      for (const suffix of ['', '-wal', '-shm']) {
        try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
      }
      try { fs.rmdirSync(dir); } catch { /* ignore */ }
    },
  };
}

const legs: Leg[] = [
  {
    name: 'sqlite',
    boot: async () => {
      const { dbPath, cleanup } = tmpDbPath('revisions');
      const tzun = await Tzun.init({ dbPath });
      return { tzun, teardown: async () => { await tzun.close(); cleanup(); } };
    },
  },
  {
    name: 'memory',
    boot: async () => {
      const tzun = await Tzun.init();
      return { tzun, teardown: async () => tzun.close() };
    },
  },
];

const captureInput = (label: string) => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { label },
  action: 'approved',
  reason: `Reason for ${label}`,
});

/**
 * Rewrite a stored payload and RECOMPUTE its digest — the reseat's first half,
 * applied BEHIND the adapter's back (`rewriteStoredEnvelope`), which is where
 * an attacker with store-write access operates. Assigning to what `retrieve()`
 * returns changes a detached copy and the store does not move.
 */
async function rewriteAndRehash(
  storage: StorageAdapter,
  evidenceId: string,
  newReason: string,
): Promise<string> {
  let newDigest = '';
  await rewriteStoredEnvelope(storage, evidenceId, (envelope) => {
    envelope.payload.reason = newReason;
    const schema = new SchemaRegistry().get(envelope.payload.schemaVersion)!;
    newDigest = computeDigest(
      canonicalSerialize(envelope.payload as unknown as Record<string, unknown>, schema.hashedFieldSet),
    );
    envelope.integrity.canonicalDigest = newDigest;
  });
  return newDigest;
}

describe.each(legs)('append-only revision log ($name)', ({ boot }) => {
  let tzun: Tzun;
  let teardown: () => Promise<void>;

  beforeEach(async () => { ({ tzun, teardown } = await boot()); });
  afterEach(async () => { await teardown(); });

  it('store() writes revision 0 carrying the capture digest, link and actor', async () => {
    const result = await tzun.capture(captureInput('first'));
    const storage = tzun.getStorage();
    const evidenceId = result.envelope.payload.evidenceId;

    const revisions = await storage.listEnvelopeRevisions(evidenceId);
    expect(revisions).toHaveLength(1);
    expect(revisions[0]).toMatchObject({
      evidenceId,
      revisionNo: 0,
      cause: 'capture',
      canonicalDigest: result.envelope.integrity.canonicalDigest,
      // Genesis: the first record has no predecessor to link to, and the log
      // records that as null rather than as the string "null", which would be
      // indistinguishable from a real link with that value.
      chainLink: null,
    });
    expect(revisions[0].recordedAt).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);
    // Attributed to the capturing actor, taken from the decision_captured
    // custody entry — not to the SDK, and never to the empty string.
    expect(revisions[0].actor).toBe(result.envelope.custodyChain[0].actor);
    expect(revisions[0].actor).not.toBe('');
  });

  it('the second record links, and its revision 0 records that link', async () => {
    await tzun.capture(captureInput('first'));
    const second = await tzun.capture(captureInput('second'));
    const revisions = await tzun.getStorage().listEnvelopeRevisions(second.envelope.payload.evidenceId);
    expect(revisions).toHaveLength(1);
    expect(revisions[0].chainLink).toBe(second.envelope.integrity.chainLink);
    expect(revisions[0].chainLink).not.toBeNull();
  });

  it('getCaptureDigests answers the whole chain in one call, and omits ids it has no revision 0 for', async () => {
    const a = await tzun.capture(captureInput('a'));
    const b = await tzun.capture(captureInput('b'));
    const storage = tzun.getStorage();

    const ids = [a.envelope.payload.evidenceId, b.envelope.payload.evidenceId, 'never-captured'];
    const digests = await storage.getCaptureDigests(ids);

    expect(digests[a.envelope.payload.evidenceId]).toBe(a.envelope.integrity.canonicalDigest);
    expect(digests[b.envelope.payload.evidenceId]).toBe(b.envelope.integrity.canonicalDigest);
    // ABSENT, not null and not '': an id the log cannot speak for must not be
    // mistakable for one it is vouching for. Callers read absence as
    // "unprovable", which is what a pre-0.3.16 record is.
    expect('never-captured' in digests).toBe(false);
    expect(await storage.getCaptureDigests([])).toEqual({});
  });

  it('a rewritten-and-rehashed payload is digest_superseded even though it hashes to its stored digest', async () => {
    await tzun.capture(captureInput('a'));
    const victim = await tzun.capture(captureInput('b'));
    await tzun.capture(captureInput('c'));
    const storage = tzun.getStorage();
    const victimId = victim.envelope.payload.evidenceId;

    const captureDigest = victim.envelope.integrity.canonicalDigest;
    const forgedDigest = await rewriteAndRehash(storage, victimId, 'Approved — the approver never wrote this');
    expect(forgedDigest).not.toBe(captureDigest);

    const result = await tzun.verifyChainCompleteness();
    // Not a digest MISMATCH: the record does hash to the digest it now
    // carries, so only the log's capture digest can expose it.
    expect(result.digestMismatches).toEqual([]);
    expect(result.digestSuperseded).toEqual([victimId]);
    expect(result.valid).toBe(false);
    expect((await storage.getCaptureDigests([victimId]))[victimId]).toBe(captureDigest);
  });

  it('an attestation retry writes a revision with cause attestation_retry and does NOT trip the superseded check', async () => {
    const captured = await tzun.capture(captureInput('attested'));
    const storage = tzun.getStorage();
    const evidenceId = captured.envelope.payload.evidenceId;

    await storage.updateAttestation(
      evidenceId,
      { rfc3161Token: 'dGVzdC10b2tlbg==' },
      'complete',
    );

    const revisions = await storage.listEnvelopeRevisions(evidenceId);
    expect(revisions.map((r) => r.cause)).toEqual(['capture', 'attestation_retry']);
    expect(revisions[1].revisionNo).toBe(1);
    expect(revisions[1].actor).toBe('tzun-attestation');
    // The digest is carried forward UNCHANGED, and that is the point: the
    // one permitted mutation touches neither payload nor integrity, so the
    // row proves the retry superseded nothing.
    expect(revisions[1].canonicalDigest).toBe(revisions[0].canonicalDigest);
    expect(revisions[1].chainLink).toBe(revisions[0].chainLink);

    const result = await tzun.verifyChainCompleteness();
    expect(result.digestSuperseded).toEqual([]);
    expect(result.valid).toBe(true);
    // And the retry really did land — otherwise this would pass vacuously.
    expect((await storage.retrieve(evidenceId))!.attestationStatus).toBe('complete');
  });

  it('a rewritten payload keeps its ORIGINAL revision 0 — the log is not moved by the tamper', async () => {
    const captured = await tzun.capture(captureInput('rewrite-me'));
    const storage = tzun.getStorage();
    const evidenceId = captured.envelope.payload.evidenceId;
    const captureDigest = captured.envelope.integrity.canonicalDigest;

    await rewriteAndRehash(storage, evidenceId, 'Approved — retroactively edited');

    const revisions = await storage.listEnvelopeRevisions(evidenceId);
    expect(revisions.filter((r) => r.revisionNo === 0)).toHaveLength(1);
    expect(revisions[0].canonicalDigest).toBe(captureDigest);
    expect((await storage.getCaptureDigests([evidenceId]))[evidenceId]).toBe(captureDigest);
  });
});

/**
 * The DEMO REWRITE PATTERN — delete the row through the tamper hook, store a
 * rewritten copy under the same id — is the one path by which `store()` can
 * ever see an evidenceId it already holds a revision 0 for (it refuses a
 * duplicate id outright otherwise). The capture revision must survive it:
 * overwriting it would let "delete and put a rewritten copy back" redefine
 * what the record was captured as, which is the laundering this log refuses.
 */
describe.each([
  { name: 'memory', make: () => new MemoryStorageAdapter() as StorageAdapter },
  { name: 'sqlite', make: () => new SqliteStorageAdapter(':memory:') as StorageAdapter },
])('revision 0 is write-once per evidenceId ($name)', ({ make }) => {
  it('a delete-and-restore under the same id keeps the ORIGINAL capture digest', async () => {
    const adapter = make();
    const spy = jest.spyOn(console, 'error').mockImplementation(() => { /* silenced */ });
    const saved = process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
    process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
    try {
      const envelope = minimalEnvelope('write-once-1');
      await adapter.store(envelope, 'default');
      await (adapter as unknown as { armDemoTamperHooks(): Promise<void> }).armDemoTamperHooks();
      await adapter.deleteEnvelopeForDemo!('write-once-1');

      const rewritten = minimalEnvelope('write-once-1');
      rewritten.payload.reason = 'Approved — retroactively edited';
      rewritten.integrity.canonicalDigest = 'b'.repeat(64);
      await adapter.store(rewritten, 'default');

      const revisions = await adapter.listEnvelopeRevisions('write-once-1');
      expect(revisions.filter((r) => r.revisionNo === 0)).toHaveLength(1);
      expect(revisions[0].canonicalDigest).toBe('a'.repeat(64));
      expect((await adapter.getCaptureDigests(['write-once-1']))['write-once-1']).toBe('a'.repeat(64));
      // Which makes the rewrite visible rather than laundered.
      expect((await adapter.retrieve('write-once-1'))!.integrity.canonicalDigest).toBe('b'.repeat(64));
    } finally {
      if (saved === undefined) delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
      else process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = saved;
      spy.mockRestore();
      await adapter.close?.();
    }
  });
});

describe('revision rows are append-only in the database (SQLite)', () => {
  let dbPath: string;
  let cleanup: () => void;

  beforeEach(() => { ({ dbPath, cleanup } = tmpDbPath('append-only')); });
  afterEach(() => cleanup());

  async function captureOne(): Promise<string> {
    const tzun = await Tzun.init({ dbPath });
    try {
      const result = await tzun.capture(captureInput('victim'));
      return result.envelope.payload.evidenceId;
    } finally {
      await tzun.close();
    }
  }

  it('a DELETE against the revision rows is refused by the database, not merely unimplemented', async () => {
    const evidenceId = await captureOne();
    const db = new Database(dbPath);
    try {
      // The edit an insider makes with the file open in sqlite3, outside the
      // SDK entirely. custody_entries already refuses this; the revision log
      // has to, or removing revision 0 leaves the record as silent as one
      // captured before 0.3.16 — a record with no capture revision reads as
      // "unprovable", which is precisely what the attacker wants.
      expect(() =>
        db.prepare('DELETE FROM envelope_revisions WHERE evidence_id = ?').run(evidenceId),
      ).toThrow(/append-only \(DELETE refused\)/);
      expect(() =>
        db.prepare('UPDATE envelope_revisions SET canonical_digest = ? WHERE evidence_id = ?')
          .run('f'.repeat(64), evidenceId),
      ).toThrow(/append-only \(UPDATE refused\)/);
      const rows = db
        .prepare('SELECT revision_no FROM envelope_revisions WHERE evidence_id = ?')
        .all(evidenceId) as Array<{ revision_no: number }>;
      expect(rows.map((r) => r.revision_no)).toEqual([0]);
    } finally {
      db.close();
    }
  });

  it('the capture probe is served by the partial covering index, not a table scan', async () => {
    await captureOne();
    const db = new Database(dbPath);
    try {
      const plan = db
        .prepare(
          'EXPLAIN QUERY PLAN SELECT canonical_digest FROM envelope_revisions WHERE evidence_id = ? AND revision_no = ?',
        )
        .all('x', 0) as Array<{ detail: string }>;
      const detail = plan.map((r) => r.detail).join(' | ');
      // The O(1) probe, pinned: an index SEARCH keyed on BOTH columns, never
      // a scan. Which of the two indexes the planner picks is its business —
      // the primary key (evidence_id, revision_no) serves the seek, the
      // partial covering index serves it index-only — but a plan that reads
      // "SCAN envelope_revisions" is O(rows) per record and would make this
      // check something a caller switches off. A table born without either
      // index gives exactly that, which is what this asserts against.
      expect(detail).toContain('SEARCH envelope_revisions USING');
      expect(detail).toMatch(/evidence_id=\? AND revision_no=\?/);
      expect(detail).not.toContain('SCAN envelope_revisions');
    } finally {
      db.close();
    }
  });
});

describe('the adapters expose no path to remove or rewrite a revision row', () => {
  it('have no mutator for the log, and hand out detached copies', async () => {
    const adapter = new MemoryStorageAdapter();
    const sqlite = new SqliteStorageAdapter(':memory:');
    try {
      // Structural, because there is no trigger to fire: the guarantee on the
      // double is that the surface has nothing on it that could remove a row.
      // A `deleteEnvelopeRevision` appearing on either adapter should fail
      // here rather than be discovered by an auditor.
      for (const surface of [adapter, sqlite]) {
        const names = new Set<string>();
        for (
          let proto: object | null = surface;
          proto && proto !== Object.prototype;
          proto = Object.getPrototypeOf(proto) as object | null
        ) {
          for (const n of Object.getOwnPropertyNames(proto)) names.add(n);
        }
        expect(names.has('listEnvelopeRevisions')).toBe(true);
        expect(names.has('getCaptureDigests')).toBe(true);
        // Nothing that could take a row away or move one. The adapters' own
        // append helpers are allowed — they only ever push, and the capture
        // row is written conditionally — but a `deleteEnvelopeRevision` or a
        // `setRevisionDigest` appearing on either surface should fail here
        // rather than be discovered by an auditor.
        const destructive = [...names].filter((n) =>
          /^(delete|remove|drop|clear|purge|overwrite|rewrite|set|update|reset)[A-Za-z]*Revision/i.test(n),
        );
        expect(destructive).toEqual([]);
      }

      // A caller that edits what it was handed must not reach the store.
      const envelope = minimalEnvelope('detach-1');
      await adapter.store(envelope, 'default');
      const rows = await adapter.listEnvelopeRevisions('detach-1');
      rows[0].canonicalDigest = 'mutated-by-the-caller';
      const again = await adapter.listEnvelopeRevisions('detach-1');
      expect(again[0].canonicalDigest).toBe(envelope.integrity.canonicalDigest);
    } finally {
      await sqlite.close();
      await adapter.close?.();
    }
  });
});

/** The smallest envelope an adapter will accept, for adapter-level cases. */
function minimalEnvelope(evidenceId: string): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'sys',
      aiOutput: { r: 1 },
      action: 'approved',
      reason: 'ok',
      capturedAt: '2026-09-12T00:00:00.000Z',
      sequenceNumber: 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: 'a'.repeat(64), chainLink: null },
    nonRepudiation: {},
    custodyChain: [
      { timestamp: '2026-09-12T00:00:00.000Z', actor: 'jane', action: 'decision_captured', systemId: 'sys' },
    ],
    attestationStatus: 'none',
  };
}
