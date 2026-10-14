/**
 * vectors/store-generation-vectors.json (Record §4.1): the engine
 * names each record's generation and the fact a mismatch carries, as the file
 * states. The Python half is tests/cross-sdk/test_store_generation_vectors.py.
 */
import {
  FIELD_SET_0_7,
  FIELD_SET_BEFORE_0_7,
  V1_0_HASHED_FIELDS,
  earlierFieldSet,
  recordFieldSetGeneration,
  recordPredatesSignoffExpectation,
  verifyEnvelope,
} from '@tzun/engine';
import { vectorFile } from './vectors';

type Case = Record<string, any>;
const v = vectorFile<Record<string, any>>('store-generation-vectors.json');

describe('store generation vectors', () => {
  it('names the three field sets', () => {
    expect(v.fieldSets).toEqual({ '0.8': [...V1_0_HASHED_FIELDS], '0.7': [...FIELD_SET_0_7], 'before-0.7': [...FIELD_SET_BEFORE_0_7] });
  });
  it.each(v.records as Case[])('record: $case', (c) => {
    expect(recordFieldSetGeneration(c.envelope)).toBe(c.expect.generation);
    expect(earlierFieldSet(c.envelope.payload, c.envelope.integrity.canonicalDigest)).toBe(c.expect.fieldSet);
    const result = verifyEnvelope(c.envelope);
    expect(result.verified).toBe(c.expect.verified);
    expect(result.fieldSet ?? null).toBe(c.expect.fieldSet);
    expect(recordPredatesSignoffExpectation(c.envelope)).toBe(c.expect.predatesSignoffExpectation);
  });
  it.each(v.stores as Case[])('store: $case', (c) => {
    const generations = c.envelopes.map((e: unknown) => recordFieldSetGeneration(e));
    expect(generations[0]).toBe(c.expect.generation);
    expect(generations[0] === '0.8').toBe(c.expect.opens);
    if (c.expect.opens) {
      const tampered = c.envelopes.flatMap((e: Case, index: number) =>
        index > 0 && generations[index] !== '0.8' ? [{ index, fieldSet: earlierFieldSet(e.payload, e.integrity.canonicalDigest) }] : []);
      expect(tampered).toEqual(c.expect.tampered);
    }
  });
});
