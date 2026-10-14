import { computeDigest, EvidenceChain } from './index';
import { createHash } from 'crypto';

test('evidence canonicalDigest is bare 64-hex (no prefix)', () => {
  const d = computeDigest('{"a":1}');
  expect(d).toMatch(/^[0-9a-f]{64}$/);
  expect(d.startsWith('sha256:')).toBe(false);
});

test('chainLink = SHA-256(prev + cur) bare hex; genesis is null', () => {
  const chain = new EvidenceChain();
  expect(chain.computeLink('aa')).toBeNull(); // no prior digest restored → genesis
  chain.restore('prev');
  const expected = createHash('sha256').update('prev' + 'cur', 'utf8').digest('hex');
  expect(chain.computeLink('cur')).toBe(expected);
});
