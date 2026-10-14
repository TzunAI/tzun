import { computeDigest } from '@tzun/engine';
import { canonicalSerialize } from '@tzun/engine';

const V1_FIELDS = ['action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider', 'evidenceId', 'links', 'reason', 'sequenceNumber', 'signoffExpectation'];

describe('computeDigest', () => {
  it('produces a 64-character hex string (SHA-256)', () => {
    const canonical = canonicalSerialize(
      {
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        evidenceId: 'abc',
        aiSystemId: 'sys1',
        aiOutput: { r: 'approve' },
        action: 'approved',
        reason: 'ok',
        capturedAt: '2026-01-01T00:00:00Z',
        sequenceNumber: 1,
      },
      V1_FIELDS
    );
    const digest = computeDigest(canonical);
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces identical digest for identical input', () => {
    const fields = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId: 'abc',
      aiSystemId: 'sys1',
      aiOutput: { r: 'approve' },
      action: 'approved',
      reason: 'ok',
      capturedAt: '2026-01-01T00:00:00Z',
      sequenceNumber: 1,
    };
    const c1 = canonicalSerialize(fields, V1_FIELDS);
    const c2 = canonicalSerialize(fields, V1_FIELDS);
    expect(computeDigest(c1)).toBe(computeDigest(c2));
  });

  it('produces different digest when any field changes', () => {
    const base = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId: 'abc',
      aiSystemId: 'sys1',
      aiOutput: { r: 'approve' },
      action: 'approved',
      reason: 'ok',
      capturedAt: '2026-01-01T00:00:00Z',
      sequenceNumber: 1,
    };
    const modified = { ...base, reason: 'changed reason' };
    const d1 = computeDigest(canonicalSerialize(base, V1_FIELDS));
    const d2 = computeDigest(canonicalSerialize(modified, V1_FIELDS));
    expect(d1).not.toBe(d2);
  });
});
