import {
  DigestComputer,
  CpuDigestComputer,
  getDefaultDigestComputer,
  setDefaultDigestComputer,
} from '@tzun/engine';
import { canonicalSerialize } from '@tzun/engine';

const V1_FIELDS = [
  'aiOutput', 'aiSystemId', 'capturedAt', 'evidenceId',
  'action', 'reason', 'sequenceNumber',
];

describe('DigestComputer', () => {
  describe('CpuDigestComputer', () => {
    const computer = new CpuDigestComputer();

    it('backend is "cpu"', () => {
      expect(computer.backend).toBe('cpu');
    });

    it('computeDigest produces 64-char hex string', () => {
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
        V1_FIELDS,
      );
      const digest = computer.computeDigest(canonical);
      expect(digest).toMatch(/^[a-f0-9]{64}$/);
    });

    it('produces identical digest for identical input', () => {
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
        V1_FIELDS,
      );
      expect(computer.computeDigest(canonical)).toBe(computer.computeDigest(canonical));
    });

    it('produces different digest for different input', () => {
      const c1 = canonicalSerialize(
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
        V1_FIELDS,
      );
      const c2 = canonicalSerialize(
        {
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          evidenceId: 'abc',
          aiSystemId: 'sys1',
          aiOutput: { r: 'deny' },
          action: 'approved',
          reason: 'ok',
          capturedAt: '2026-01-01T00:00:00Z',
          sequenceNumber: 1,
        },
        V1_FIELDS,
      );
      expect(computer.computeDigest(c1)).not.toBe(computer.computeDigest(c2));
    });

    it('computeBatch produces same results as sequential computeDigest calls', () => {
      const canonicals = [
        canonicalSerialize(
          {
            decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
            evidenceId: 'a',
            aiSystemId: 'sys1',
            aiOutput: { r: 'approve' },
            action: 'approved',
            reason: 'ok',
            capturedAt: '2026-01-01T00:00:00Z',
            sequenceNumber: 1,
          },
          V1_FIELDS,
        ),
        canonicalSerialize(
          {
            decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
            evidenceId: 'b',
            aiSystemId: 'sys1',
            aiOutput: { r: 'deny' },
            action: 'denied',
            reason: 'no',
            capturedAt: '2026-01-02T00:00:00Z',
            sequenceNumber: 2,
          },
          V1_FIELDS,
        ),
        canonicalSerialize(
          {
            decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
            evidenceId: 'c',
            aiSystemId: 'sys2',
            aiOutput: { r: 'review' },
            action: 'reviewed',
            reason: 'maybe',
            capturedAt: '2026-01-03T00:00:00Z',
            sequenceNumber: 3,
          },
          V1_FIELDS,
        ),
      ];

      const sequential = canonicals.map(c => computer.computeDigest(c));
      const batch = computer.computeBatch(canonicals);

      expect(batch).toEqual(sequential);
    });

    it('computeBatch handles empty array', () => {
      expect(computer.computeBatch([])).toEqual([]);
    });

    it('computeBatch handles single element', () => {
      const canonical = canonicalSerialize(
        {
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          evidenceId: 'abc',
          aiSystemId: 'sys1',
          aiOutput: {},
          action: 'ok',
          reason: 'ok',
          capturedAt: '2026-01-01T00:00:00Z',
          sequenceNumber: 1,
        },
        V1_FIELDS,
      );
      const batch = computer.computeBatch([canonical]);
      expect(batch).toEqual([computer.computeDigest(canonical)]);
    });
  });

  describe('getDefaultDigestComputer / setDefaultDigestComputer', () => {
    it('default is CpuDigestComputer', () => {
      const dc = getDefaultDigestComputer();
      expect(dc.backend).toBe('cpu');
    });

    it('setDefaultDigestComputer replaces the default', () => {
      const original = getDefaultDigestComputer();

      const custom: DigestComputer = {
        backend: 'test-backend',
        computeDigest: (canonical: string) => 'custom-' + canonical.length,
        computeBatch: (canonicals: string[]) => canonicals.map(c => 'custom-' + c.length),
      };

      setDefaultDigestComputer(custom);
      expect(getDefaultDigestComputer().backend).toBe('test-backend');

      // Restore
      setDefaultDigestComputer(original);
      expect(getDefaultDigestComputer().backend).toBe('cpu');
    });
  });
});
