/**
 * vectors/contributions-vectors.json (Record §7): the engine gives
 * every answer the file states. The Python half is
 * tests/cross-sdk/test_contributions_vectors.py.
 */
import { buildContributions, checkContributions, contributionsViolation, outputDigest, stepDigest } from '@tzun/engine';
import { codeOf, vectorFile } from './vectors';

type Case = Record<string, any>;
const v = vectorFile<Record<string, Case[]>>('contributions-vectors.json');

describe('contributions vectors', () => {
  it('holds every part', () => {
    for (const part of ['outputDigests', 'stepDigests', 'shapes', 'builder', 'checks']) expect(v[part].length).toBeGreaterThan(0);
  });
  it.each(v.outputDigests)('output digest: $label', (c) => expect(outputDigest(c.value)).toBe(c.digest));
  it.each(v.stepDigests)('step digest: $label', (c) => expect(stepDigest(c.step)).toBe(c.digest));
  it.each(v.shapes)('shape: $case', (c) => expect(codeOf(contributionsViolation(c.value, c.context))).toEqual(c.violation));
  it.each(v.builder)('builder: $case', (c) => {
    if (c.built !== undefined) {
      expect(buildContributions(c.input, c.context)).toEqual(c.built);
    } else {
      expect(() => buildContributions(c.input, c.context)).toThrow(expect.objectContaining(c.refused));
    }
  });
  it.each(v.checks)('check: $case', (c) => expect(checkContributions(c.payload)).toEqual(c.expect));
});
