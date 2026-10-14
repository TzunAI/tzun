/**
 * vectors/v1.0-canonical-vectors.json and vectors/v1.0-integrity-vectors.json
 * under the v1.0 hashed field set as revised in 0.8.0 (Record §4.1):
 * every envelope input serializes to its canonical bytes both whole and under
 * the eleven names, and every negative input is refused under the eleven
 * names. The Python half is tests/cross-sdk/test_canonical_parity.py and
 * tests/cross-sdk/test_integrity_parity.py.
 */
import { EvidenceChain, V1_0_HASHED_FIELDS, canonicalSerialize, canonicalSerializeDescriptor, canonicalSerializeValue, computeDigest } from '@tzun/engine';
import { materialize, vectorFile } from './vectors';

type Case = Record<string, any>;
const canonicalFile = vectorFile<{ vectors: Case[]; negativeVectors: Case[] }>('v1.0-canonical-vectors.json');
const integrity = vectorFile<{ vectors: Case[] }>('v1.0-integrity-vectors.json');
const FIELDS = [...V1_0_HASHED_FIELDS];
const undefinedMarker = (value: unknown): unknown => {
  if (value === 'UNDEFINED_MARKER') return undefined;
  if (Array.isArray(value)) return value.map(undefinedMarker);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, x]) => [k, undefinedMarker(x)]));
  return value;
};

describe('v1.0 canonical vectors', () => {
  it('every envelope input holds exactly the eleven hashed names', () => {
    for (const c of canonicalFile.vectors.filter((x) => x.kind === 'envelope-v1.0')) expect(Object.keys(c.input).sort()).toEqual([...FIELDS].sort());
  });
  it.each(canonicalFile.vectors)('$id: $description', (c) => {
    if (c.kind === 'descriptor') {
      expect(canonicalSerializeDescriptor(c.input)).toBe(c.canonical);
      return;
    }
    const input = undefinedMarker(c.input) as Record<string, unknown>;
    expect(canonicalSerialize(input, FIELDS)).toBe(c.canonical);
    expect(canonicalSerializeValue(input)).toBe(c.canonical);
  });
  it.each(canonicalFile.negativeVectors)('$id refused: $description', (c) => {
    expect(() => canonicalSerialize(materialize(c.input) as Record<string, unknown>, FIELDS)).toThrow(new RegExp(c.expectError, 'i'));
  });
});

describe('v1.0 integrity vectors', () => {
  it.each(integrity.vectors)('$id', (c) => {
    if (c.kind === 'chain-link') {
      if (c.previousDigest === null) {
        expect(c.expectedChainLink).toBeNull();
        return;
      }
      const chain = new EvidenceChain();
      chain.restore(c.previousDigest);
      expect(chain.computeLink(c.currentDigest)).toBe(c.expectedChainLink);
      return;
    }
    const canonical = c.input !== undefined ? canonicalSerialize(c.input, c.hashedFields) : c.canonical;
    if (c.input !== undefined) expect(canonical).toBe(c.expectedCanonical);
    expect(computeDigest(canonical)).toBe(c.expectedDigest);
  });
});
