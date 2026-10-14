import { Tzun } from '../../../src/sdk';

describe('smoke', () => {
  it('captures and verifies', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    const r = await tzun.capture({
      aiOutput: { x: 1 },
      action: 'approve',
      reason: 'fine',
      decider: { kind: 'human', id: 'acct:u-1' },
    });
    expect(r.failure).toBeUndefined();
    expect(r.stored).toBe(true);
    const v = await tzun.verify(r.envelope.payload.evidenceId);
    expect(v.verified).toBe(true);
    const r2 = await tzun.capture({
      aiOutput: { x: 2 },
      action: 'approve',
      reason: 'fine',
      decider: { kind: 'human', id: 'acct:u-1', commit: true },
      links: [{ rel: 'derivedFrom', target: { digest: r.envelope.integrity.canonicalDigest, external: true } }],
    });
    expect(r2.failure?.diagnosticMetadata).toBeUndefined();
    expect(r2.deciderOpening?.id).toBe('acct:u-1');
    expect(r2.envelope.payload.decider?.id).toMatch(/^cmt:[0-9a-f]{64}$/);
    expect(await tzun.deciders.opening(r2.envelope.payload.evidenceId)).toEqual(r2.deciderOpening);
    expect((await tzun.verify(r2.envelope.payload.evidenceId)).verified).toBe(true);
    await tzun.close();
  });
});
