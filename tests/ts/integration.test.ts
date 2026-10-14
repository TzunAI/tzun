import { Tzun } from '../../src/sdk/index';

describe('Integration: full capture-verify flow', () => {
  it('captures multiple records with chain linking and verifies each', async () => {
    const tzun = await Tzun.init();

    // Capture 3 records
    const results = [];
    for (let i = 1; i <= 3; i++) {
      const result = await tzun.capture({
        aiSystemId: 'integration-test',
        aiOutput: { step: i, recommendation: `action-${i}` },
        action: `approved-${i}`,
        reason: `Reason for step ${i}`,
        decider: { kind: 'human' as const, id: 'acct:test-example.com', agent: null, credential: null, freshness: null },
      });
      expect(result.stored).toBe(true);
      results.push(result);
    }

    // First record has null chainLink
    expect(results[0].envelope.integrity.chainLink).toBeNull();

    // Subsequent records have non-null chainLink
    expect(results[1].envelope.integrity.chainLink).toMatch(/^[a-f0-9]{64}$/);
    expect(results[2].envelope.integrity.chainLink).toMatch(/^[a-f0-9]{64}$/);

    // Each record has a unique evidenceId
    const ids = results.map(r => r.envelope.payload.evidenceId);
    expect(new Set(ids).size).toBe(3);

    // Each record has a unique digest
    const digests = results.map(r => r.envelope.integrity.canonicalDigest);
    expect(new Set(digests).size).toBe(3);

    // Verify each record, passing previousDigest for chained records
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const previousDigest = i > 0 ? results[i - 1].envelope.integrity.canonicalDigest : undefined;
      const verification = await tzun.verify(result.envelope.payload.evidenceId, previousDigest);
      expect(verification.verified).toBe(true);
      expect(verification.storedDigest).toBe(result.envelope.integrity.canonicalDigest);
      expect(verification.recomputedDigest).toBe(result.envelope.integrity.canonicalDigest);
    }

    // List all records
    const storage = tzun.getStorage();
    const all = await storage.list();
    expect(all).toHaveLength(3);

    // List with filter
    const filtered = await storage.list({ aiSystemId: 'integration-test' });
    expect(filtered).toHaveLength(3);

    const noResults = await storage.list({ aiSystemId: 'non-existent' });
    expect(noResults).toHaveLength(0);
  });

  it('handles failure gracefully and records failure', async () => {
    const tzun = await Tzun.init();

    const result = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { text: 'hello' },
      action: '',
      reason: '',
    });

    expect(result.stored).toBe(false);
    expect(result.failure).toBeDefined();
    expect(result.failure!.failureType).toBe('validation_failure');
  });
});
