import { testEvidenceId } from './helpers/evidence-id';
/**
 * capturedAt must not run backwards along a chain.
 *
 * This is the half the RFC 3161 token structurally CANNOT check. A token proves
 * an upper bound — "this digest existed no later than genTime" — which can
 * never contradict a claim of EARLIER creation, and backdating is the direction
 * with legal value. verifyAttestation's capturedAt check therefore rules only
 * on `capturedAt > genTime`, the impossible direction, and deliberately
 * declines to judge a large positive skew because retryPendingAttestations()
 * produces one legitimately.
 *
 * Chain order closes that. Records are appended under a per-instance mutex in
 * sequence order, so a later record's capturedAt should not predate an earlier
 * one's. A regression means the clock moved between two captures.
 *
 * WHY IT IS NOT FOLDED INTO `valid`. A regression is suspicious, not proof: an
 * NTP correction produces one honestly, and capturedAt is in the hashed field
 * set, so a chain marked invalid for a clock blip could never be repaired —
 * nothing can renumber or restamp a record without breaking every digest over
 * it. It is reported on its own channel instead: `timeRegressions` here, and in
 * ScheduledScanner a `captured_at_regression` event at warning severity that is
 * not counted in the pass's `issuesFound`.
 */
import { verifyChainCompleteness, assembleEnvelope } from '@tzun/engine';
import type { EvidenceEnvelope, StorageAdapter } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../src/storage/memory';

/** Append `n` records whose capturedAt instants are given, in sequence order. */
async function chainWithTimes(times: string[]): Promise<StorageAdapter> {
  const storage = new MemoryStorageAdapter();
  let previousDigest: string | undefined;
  for (let i = 0; i < times.length; i++) {
    const envelope: EvidenceEnvelope = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'sys-1',
        aiOutput: { recommendation: `r${i + 1}` },
        action: 'approved',
        reason: 'looks right',
      } as never, { previousDigest: previousDigest, sequenceNumber: i + 1, signoffExpectation: null, capturedAt: times[i], evidenceId: testEvidenceId(`ev-${i + 1}`) });
    await storage.store(envelope);
    previousDigest = envelope.integrity.canonicalDigest;
  }
  return storage;
}

const T = (iso: string) => new Date(iso).toISOString();

describe('chain completeness reports capturedAt running backwards', () => {
  it('reports nothing when time moves forward', async () => {
    const storage = await chainWithTimes([
      T('2026-09-17T10:00:00.000Z'),
      T('2026-09-17T10:00:05.000Z'),
      T('2026-09-17T10:00:11.000Z'),
    ]);
    const result = await verifyChainCompleteness(storage);
    expect(result.timeRegressions).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it('names the record whose capturedAt predates the one before it', async () => {
    // Record 2 was minted on a clock set back an hour.
    const storage = await chainWithTimes([
      T('2026-09-17T10:00:00.000Z'),
      T('2026-09-17T09:00:00.000Z'),
      T('2026-09-17T10:00:11.000Z'),
    ]);
    const result = await verifyChainCompleteness(storage);
    expect(result.timeRegressions).toEqual([testEvidenceId('ev-2')]);
  });

  it('does NOT mark the chain invalid, because an NTP correction is not tampering', async () => {
    // capturedAt is in the hashed field set, so a chain condemned for a clock
    // blip could never be repaired. The finding is reported, not fatal.
    const storage = await chainWithTimes([
      T('2026-09-17T10:00:00.000Z'),
      T('2026-09-17T09:00:00.000Z'),
    ]);
    const result = await verifyChainCompleteness(storage);
    expect(result.timeRegressions).toEqual([testEvidenceId('ev-2')]);
    expect(result.valid).toBe(true);
  });

  it('absorbs sub-second jitter rather than reporting it', async () => {
    const storage = await chainWithTimes([
      T('2026-09-17T10:00:00.500Z'),
      T('2026-09-17T10:00:00.200Z'),
    ]);
    const result = await verifyChainCompleteness(storage);
    expect(result.timeRegressions).toEqual([]);
  });

  it('honours an explicit tolerance', async () => {
    const storage = await chainWithTimes([
      T('2026-09-17T10:00:10.000Z'),
      T('2026-09-17T10:00:05.000Z'),
    ]);
    // 5s back: inside a 10s tolerance, outside a 1s one.
    expect((await verifyChainCompleteness(storage, undefined, { capturedAtToleranceMs: 10_000 })).timeRegressions).toEqual([]);
    expect((await verifyChainCompleteness(storage, undefined, { capturedAtToleranceMs: 1_000 })).timeRegressions).toEqual([testEvidenceId('ev-2')]);
  });

  it('reports each regression, not just the first', async () => {
    const storage = await chainWithTimes([
      T('2026-09-17T10:00:00.000Z'),
      T('2026-09-17T09:00:00.000Z'),
      T('2026-09-17T10:00:30.000Z'),
      T('2026-09-17T08:00:00.000Z'),
    ]);
    const result = await verifyChainCompleteness(storage);
    expect(result.timeRegressions).toEqual([testEvidenceId('ev-2'), testEvidenceId('ev-4')]);
  });

  it('ignores an unreadable capturedAt rather than throwing or calling it a regression', async () => {
    // capturedAt reaches a verifier as stored JSON. A malformed value is not a
    // time regression — it is a different defect, and digestMismatches is the
    // check that owns a payload that does not hash to its own digest.
    const storage = await chainWithTimes([T('2026-09-17T10:00:00.000Z')]);
    const stored = await storage.retrieve(testEvidenceId('ev-1'));
    (stored as unknown as { payload: { capturedAt: unknown } }).payload.capturedAt = 'not-a-date';
    await expect(verifyChainCompleteness(storage)).resolves.toBeDefined();
    const result = await verifyChainCompleteness(storage);
    expect(result.timeRegressions).toEqual([]);
  });
});
