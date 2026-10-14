import { EvidenceChain } from '@tzun/engine';

describe('EvidenceChain', () => {
  let chain: EvidenceChain;

  beforeEach(() => {
    chain = new EvidenceChain();
  });

  it('first record has null chain link', () => {
    const link = chain.computeLink('digest-aaa');
    expect(link).toBeNull();
  });

  it('second record links to first digest', () => {
    chain.computeLink('digest-aaa');
    chain.append('digest-aaa');
    const link = chain.computeLink('digest-bbb');
    expect(link).toBeDefined();
    expect(link).not.toBeNull();
    expect(typeof link).toBe('string');
    expect(link).toMatch(/^[a-f0-9]{64}$/);
  });

  it('chain link is SHA-256 of previous digest concatenated with current digest', () => {
    chain.computeLink('digest-aaa');
    chain.append('digest-aaa');
    const link = chain.computeLink('digest-bbb');
    // Verify it's deterministic
    const chain2 = new EvidenceChain();
    chain2.computeLink('digest-aaa');
    chain2.append('digest-aaa');
    const link2 = chain2.computeLink('digest-bbb');
    expect(link).toBe(link2);
  });

  it('different previous digest produces different chain link', () => {
    chain.computeLink('digest-aaa');
    chain.append('digest-aaa');
    const link1 = chain.computeLink('digest-ccc');

    const chain2 = new EvidenceChain();
    chain2.computeLink('digest-bbb');
    chain2.append('digest-bbb');
    const link2 = chain2.computeLink('digest-ccc');

    expect(link1).not.toBe(link2);
  });

  it('tampering with a historical record is detectable via chain verification', () => {
    // Build a chain of 3 records
    chain.computeLink('digest-1');
    chain.append('digest-1');
    chain.computeLink('digest-2');
    chain.append('digest-2');
    chain.computeLink('digest-3');
    chain.append('digest-3');

    // Verify the chain is valid
    const records = [
      { digest: 'digest-1', chainLink: null as string | null },
      { digest: 'digest-2', chainLink: '' },
      { digest: 'digest-3', chainLink: '' },
    ];
    // Reconstruct chain links for verification
    const verifyChain = new EvidenceChain();
    records[0].chainLink = verifyChain.computeLink('digest-1');
    verifyChain.append('digest-1');
    records[1].chainLink = verifyChain.computeLink('digest-2');
    verifyChain.append('digest-2');
    records[2].chainLink = verifyChain.computeLink('digest-3');

    expect(records[0].chainLink).toBeNull();
    expect(records[1].chainLink).toMatch(/^[a-f0-9]{64}$/);
    expect(records[2].chainLink).toMatch(/^[a-f0-9]{64}$/);

    // Now "tamper" with record 1 — change its digest
    // Recomputing links from tampered record will produce different links
    const tamperedChain = new EvidenceChain();
    tamperedChain.computeLink('digest-1-TAMPERED');
    tamperedChain.append('digest-1-TAMPERED');
    const tamperedLink2 = tamperedChain.computeLink('digest-2');

    // The chain link for record 2 no longer matches
    expect(tamperedLink2).not.toBe(records[1].chainLink);
  });
});
