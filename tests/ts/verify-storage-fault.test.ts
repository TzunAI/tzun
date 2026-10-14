/**
 * A storage fault while resolving the predecessor is an error, not a broken
 * chain.
 *
 * `resolvePredecessorDigest` makes two storage calls, `listBySequence` and
 * `getChainForRecord`. If an infrastructure fault in either (dropped
 * connection, SQLITE_BUSY, permissions) were caught and turned into
 * `undefined`, the engine would score it as `chainLinkValid: false` →
 * `verified: false`, and the REST verify route would report it as a
 * `chain_break` monitoring event.
 *
 * That is a tamper incident raised on untampered evidence because the database
 * hiccuped. A storage fault must surface as an error: `verify()` rejects with
 * it, and a healthy adapter still verifies the chain link.
 */
import { Tzun } from '../../src/sdk/index';
import type { StorageAdapter } from '@tzun/engine';

const DB_FAULT = 'SQLITE_BUSY: database is locked';

const captureInput = (label: string) => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { label },
  action: 'approved',
  reason: `Reason for ${label}`,
});

/** Two records so the second is non-genesis and actually resolves a predecessor. */
async function captureTwo(tzun: Tzun): Promise<string> {
  const first = await tzun.capture(captureInput('record-1'));
  expect(first.stored).toBe(true);
  const second = await tzun.capture(captureInput('record-2'));
  expect(second.stored).toBe(true);
  expect(second.envelope.payload.sequenceNumber).toBe(2);
  return second.envelope.payload.evidenceId;
}

describe('a storage fault during verify is an error, not a chain_break verdict', () => {
  it('verify() rejects when listBySequence rejects', async () => {
    const tzun = await Tzun.init();
    const evidenceId = await captureTwo(tzun);

    const storage = tzun.getStorage() as StorageAdapter;
    const original = storage.listBySequence.bind(storage);
    storage.listBySequence = async () => {
      throw new Error(DB_FAULT);
    };

    await expect(tzun.verify(evidenceId)).rejects.toThrow(DB_FAULT);

    storage.listBySequence = original;
  });

  it('verify() rejects when getChainForRecord rejects', async () => {
    const tzun = await Tzun.init();
    const evidenceId = await captureTwo(tzun);

    const storage = tzun.getStorage() as StorageAdapter;
    const original = storage.getChainForRecord.bind(storage);
    storage.getChainForRecord = async () => {
      throw new Error(DB_FAULT);
    };

    await expect(tzun.verify(evidenceId)).rejects.toThrow(DB_FAULT);

    storage.getChainForRecord = original;
  });

  it('a healthy adapter still verifies the chain link', async () => {
    const tzun = await Tzun.init();
    const evidenceId = await captureTwo(tzun);
    const result = await tzun.verify(evidenceId);
    expect(result.chainLinkValid).toBe(true);
    expect(result.verified).toBe(true);
  });
});
