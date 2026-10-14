/**
 * vectors/decider-vectors.json (Record §6): the engine gives every
 * answer the file states. The Python half is tests/cross-sdk/test_decider_vectors.py.
 */
import {
  checkDecider,
  deciderAgreesWithExpectation,
  deciderCommitment,
  deciderCommitmentSalt,
  deciderMaterialViolation,
  deciderViolation,
  parseFreshnessReference,
  payloadRecordRuleViolation,
  readerActorInconsistent,
  verifyDeciderOpening,
  type DeciderKind,
} from '@tzun/engine';
import { codeOf, vectorFile } from './vectors';

type Case = Record<string, any>;
const v = vectorFile<Record<string, Case[]>>('decider-vectors.json');

describe('decider vectors', () => {
  it('holds every part', () => {
    for (const part of ['shapes', 'freshness', 'consistency', 'agreement', 'material', 'rows', 'commitments', 'derivedSalts', 'commitmentRefusals', 'openings']) {
      expect(v[part].length).toBeGreaterThan(0);
    }
    expect(v.agreement).toHaveLength(16);
  });
  it.each(v.shapes)('shape: $case', (c) => expect(codeOf(deciderViolation(c.value))).toEqual(c.violation));
  it.each(v.freshness)('freshness: $case', (c) => expect(parseFreshnessReference(c.reference)).toEqual(c.parsed));
  it.each(v.consistency)('consistency: $case', (c) => {
    expect(deciderViolation({ kind: c.kind, id: c.id, agent: c.agent, credential: null, freshness: null })?.code ?? null).toBe(c.writer);
    expect(readerActorInconsistent(c.kind as DeciderKind, c.id, c.agent)).toBe(c.readerInconsistent);
  });
  it.each(v.agreement)('agreement: $case', (c) => {
    expect(deciderAgreesWithExpectation(c.kind, c.payload.signoffExpectation)).toBe(c.agrees);
    const w = payloadRecordRuleViolation(c.payload);
    expect(w && { rule: w.rule, code: w.code }).toEqual(c.writer);
    expect(checkDecider({ payload: c.payload, nonRepudiation: {} })).toEqual(c.row);
  });
  it.each(v.material)('material: $case', (c) => expect(codeOf(deciderMaterialViolation(c.decider, c.material))).toEqual(c.violation));
  it.each(v.rows)('row: $case', (c) => expect(checkDecider(c.envelope)).toEqual(c.expect));
  it.each(v.commitments)('commitment: $case', (c) => {
    expect(deciderCommitment(c.innerId, Buffer.from(c.saltHex, 'hex'))).toBe(c.commitment);
    expect(deciderCommitment(c.innerId, c.saltBase64url)).toBe(c.commitment);
  });
  it.each(v.derivedSalts)('derived salt: $idempotencyKey $innerId', (c) => {
    const salt = deciderCommitmentSalt(Buffer.from(c.secretHex, 'hex'), c.idempotencyKey, c.innerId);
    expect(salt).toBe(c.saltBase64url);
    expect(deciderCommitment(c.innerId, salt)).toBe(c.commitment);
  });
  it.each(v.commitmentRefusals)('commitment refused: $case', (c) => {
    expect(() => deciderCommitment(c.innerId, Buffer.from(c.saltHex, 'hex'))).toThrow();
  });
  it.each(v.openings)('opening: $case', (c) => expect(verifyDeciderOpening(c.id, c.opening)).toBe(c.opens));
});
