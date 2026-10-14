// tests/ts/capture-sequence-race.test.ts
//
// Concurrent captures each get their own sequence number and link to their
// own predecessor, whether they share one SDK instance or one store.
//
// `Tzun.capture()` reads `this.nextSequence` and `this.chain.getLastDigest()`,
// awaits across attestation and store I/O, and only advances them after
// `store()` resolves. Left unguarded, two overlapping captures would reserve
// the SAME sequence number and link to the SAME predecessor, an adapter would
// write both, and both callers would be told `stored: true`.
//
// The damage is not the duplicate itself. `restoreChain()` then picks whichever
// duplicate committed last as the head, orphaning the others, and every
// verifier reports chain breaks on evidence nobody touched — so real tampering
// becomes indistinguishable from ordinary load.
//
// Two mechanisms are pinned here:
//   1. a per-instance capture mutex, so concurrent captures on one instance
//      serialise and all succeed at consecutive sequences; and
//   2. `StoreOptions.expectChainHead`, a compare-and-swap the adapter applies
//      inside its atomic section, so a writer that did NOT go through that
//      mutex (a second SDK instance, a second replica) is refused rather than
//      silently writing a duplicate.
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { ChainConflictError, type EvidenceEnvelope } from '@tzun/engine';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const input = (label: string) => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { label },
  action: 'approved',
  reason: `because ${label}`,
});

function tmpDb(name: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `tzun-test-seq-race-${name}-`));
  return path.join(dir, 'tzun.db');
}

/** A 64-hex digest unique to the record: the shape of a real one, and of an evidence-log leaf. */
function digestOf(evidenceId: string): string {
  return createHash('sha256').update(evidenceId).digest('hex');
}

function envelopeAt(evidenceId: string, sequenceNumber: number): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'race-test',
      aiOutput: {},
      action: 'approved',
      reason: 'fixture',
      capturedAt: '2026-09-01T00:00:00.000Z',
      sequenceNumber,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: digestOf(evidenceId), chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

describe('concurrent capture() on one instance', () => {
  it('assigns 1..N with no duplicates on the memory adapter', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });

    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) => tzun.capture(input(`c${i}`))),
    );

    expect(results.every((r) => r.stored)).toBe(true);
    const seqs = results.map((r) => r.envelope.payload.sequenceNumber).sort((a, b) => a - b);
    expect(seqs).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(new Set(seqs).size).toBe(8);

    const completeness = await tzun.verifyChainCompleteness();
    expect(completeness.valid).toBe(true);
    expect(completeness.totalRecords).toBe(8);
    expect(completeness.brokenLinks).toEqual([]);
    await tzun.close();
  });

  it('assigns 1..N with no duplicates on the sqlite adapter', async () => {
    const dbPath = tmpDb('sqlite');
    const tzun = await Tzun.init({ mode: 'dev', dbPath });

    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) => tzun.capture(input(`c${i}`))),
    );

    expect(results.every((r) => r.stored)).toBe(true);
    const seqs = results.map((r) => r.envelope.payload.sequenceNumber).sort((a, b) => a - b);
    expect(seqs).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);

    const completeness = await tzun.verifyChainCompleteness();
    expect(completeness.valid).toBe(true);
    expect(completeness.brokenLinks).toEqual([]);
    await tzun.close();
  });

  it('links each record to its immediate predecessor under concurrency', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    await Promise.all(Array.from({ length: 5 }, (_, i) => tzun.capture(input(`c${i}`))));

    const records = await tzun.getStorage().listBySequence(1, 5);
    expect(records).toHaveLength(5);
    expect(records[0].integrity.chainLink).toBeNull(); // genesis
    for (let i = 1; i < records.length; i++) {
      // A duplicate-sequence write would leave two records linking to the SAME
      // predecessor; distinct links prove each one linked to the record before it.
      expect(records[i].integrity.chainLink).not.toBeNull();
      expect(records[i].integrity.chainLink).not.toBe(records[i - 1].integrity.chainLink);
    }
    await tzun.close();
  });
});

describe('two SDK instances sharing one store', () => {
  it('retries the stale writer onto the moved head instead of dropping its capture', async () => {
    // The adapter's compare-and-swap refusing the stale record is correct, but
    // it is not the end of the capture: the point of a compare-and-swap is to
    // retry against the value you lost to, and `capture()` does. Stopping at
    // the refusal would drop the stale writer's evidence: half of all captures
    // under two replicas, and on SQLite with alternating writers every capture
    // from one of them. The full measurement lives in
    // two-writers-chain-conflict-retry.test.ts; this is the two-instance shape.
    const dbPath = tmpDb('two-inst');
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const b = await Tzun.init({ mode: 'dev', dbPath });

    // Both booted against an empty chain, so both hold nextSequence = 1.
    const ra = await a.capture(input('from-a'));
    expect(ra.stored).toBe(true);
    expect(ra.envelope.payload.sequenceNumber).toBe(1);

    // B still believes the chain is empty. The adapter refuses the record it
    // built at sequence 1 (there is one there already, linking to nothing),
    // B adopts the head the refusal reported, rebuilds at 2 and lands it.
    const rb = await b.capture(input('from-b'));
    expect(rb.stored).toBe(true);
    expect(rb.failure).toBeUndefined();
    expect(rb.envelope.payload.sequenceNumber).toBe(2);

    // And B's view is now current: no refusal on the next one.
    const rb2 = await b.capture(input('from-b-again'));
    expect(rb2.stored).toBe(true);
    expect(rb2.envelope.payload.sequenceNumber).toBe(3);

    const completeness = await a.verifyChainCompleteness();
    expect(completeness.valid).toBe(true);
    expect(completeness.totalRecords).toBe(3);
    expect(completeness.brokenLinks).toEqual([]);

    await a.close();
    await b.close();
  });
});

describe('adapter-level compare-and-swap (StoreOptions.expectChainHead)', () => {
  for (const [name, make] of [
    ['memory', () => new MemoryStorageAdapter()],
    ['sqlite', () => new SqliteStorageAdapter(tmpDb('cas'))],
  ] as Array<[string, () => MemoryStorageAdapter | SqliteStorageAdapter]>) {
    describe(name, () => {
      it('accepts an append onto the expected head', async () => {
        const adapter = make();
        await adapter.store(envelopeAt('ev-1', 1), 'default', {
          expectChainHead: { sequence: 0, digest: null },
        });
        await adapter.store(envelopeAt('ev-2', 2), 'default', {
          expectChainHead: { sequence: 1, digest: digestOf('ev-1') },
        });
        expect(await adapter.getLastSequence()).toBe(2);
        await adapter.close();
      });

      it('refuses an append onto a stale sequence and writes nothing', async () => {
        const adapter = make();
        await adapter.store(envelopeAt('ev-1', 1), 'default', {
          expectChainHead: { sequence: 0, digest: null },
        });

        await expect(
          adapter.store(envelopeAt('ev-2', 2), 'default', {
            expectChainHead: { sequence: 0, digest: null },
          }),
        ).rejects.toThrow(ChainConflictError);

        expect(await adapter.retrieve('ev-2')).toBeNull();
        expect(await adapter.getLastSequence()).toBe(1);
        expect(await adapter.getLastDigest()).toBe(digestOf('ev-1'));
        await adapter.close();
      });

      it('refuses an append onto a stale digest even at the right sequence', async () => {
        const adapter = make();
        await adapter.store(envelopeAt('ev-1', 1), 'default', {
          expectChainHead: { sequence: 0, digest: null },
        });

        await expect(
          adapter.store(envelopeAt('ev-2', 2), 'default', {
            expectChainHead: { sequence: 1, digest: 'sha256:some-other-record' },
          }),
        ).rejects.toThrow(ChainConflictError);

        expect(await adapter.retrieve('ev-2')).toBeNull();
        await adapter.close();
      });

      it('writes without a head check when no head is expected (low-level primitive), one record per position', async () => {
        // store() is also used for imports, fixtures and recovery flows that
        // are not chain appends. Those must keep working, and a position still
        // holds one record.
        const adapter = make();
        await adapter.store(envelopeAt('ev-1', 1));
        await adapter.store(envelopeAt('ev-2', 2)); // no guard
        expect(await adapter.retrieve('ev-2')).not.toBeNull();
        await expect(adapter.store(envelopeAt('ev-3', 1))).rejects.toMatchObject({ reason: 'position_taken' });
        await adapter.close();
      });

      it('carries the expected and actual heads on the error', async () => {
        const adapter = make();
        await adapter.store(envelopeAt('ev-1', 1), 'default', {
          expectChainHead: { sequence: 0, digest: null },
        });
        try {
          await adapter.store(envelopeAt('ev-2', 2), 'default', {
            expectChainHead: { sequence: 5, digest: 'sha256:nope' },
          });
          throw new Error('expected store to reject');
        } catch (err) {
          expect(err).toBeInstanceOf(ChainConflictError);
          const e = err as ChainConflictError;
          expect(e.code).toBe('chain_conflict');
          expect(e.expected).toEqual({ sequence: 5, digest: 'sha256:nope' });
          expect(e.actual).toEqual({ sequence: 1, digest: digestOf('ev-1') });
        }
        await adapter.close();
      });
    });
  }
});
