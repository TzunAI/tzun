import { assembleEnvelope, EnvelopeInputError } from './envelope';

describe('assembleEnvelope capturedAt override', () => {
  const input = {
    aiSystemId: 'sys',
    aiOutput: { d: 1 },
    action: 'approved',
    reason: 'ok',
    decider: { kind: 'human' as const, id: 'acct:u-1', agent: null, credential: null, freshness: null },
  };

  it('carries an explicit ISO-8601 capturedAt verbatim and hashes it', () => {
    const ts = '2025-11-02T08:30:00.000Z';
    const env = assembleEnvelope(input, { capturedAt: ts });
    expect(env.payload.capturedAt).toBe(ts);
    // Digest covers capturedAt (it is in the v1.0 hashed-field set): same input,
    // different capturedAt ⇒ different digest.
    const env2 = assembleEnvelope(input, { capturedAt: '2025-11-02T09:30:00.000Z' });
    expect(env2.integrity.canonicalDigest).not.toBe(env.integrity.canonicalDigest);
  });

  it('absent override → now()', () => {
    const before = Date.now();
    const env = assembleEnvelope(input);
    const t = Date.parse(env.payload.capturedAt);
    expect(t).toBeGreaterThanOrEqual(before - 1000);
    expect(t).toBeLessThanOrEqual(Date.now() + 1000);
  });

  it('malformed override → throws', () => {
    expect(() => assembleEnvelope(input, { capturedAt: 'last tuesday' })).toThrow(/capturedAt/);
    expect(() => assembleEnvelope(input, { capturedAt: '2025-13-45T99:00:00Z' })).toThrow(/capturedAt/);
  });

  it('refuses a schema version string in place of the options object rather than misreading it', () => {
    expect(() => (assembleEnvelope as unknown as (...a: unknown[]) => unknown)(input, 'v1.0')).toThrow(EnvelopeInputError);
  });
});
