/**
 * vectors/cross-sdk-parity-vectors.json (Record §2.2): parsed by
 * JSON.parse, every case gives the bytes, digest, writer refusal and rows the
 * file states. The Python half is tests/cross-sdk/test_cross_sdk_parity_vectors.py,
 * parsing the same text with json.loads.
 */
import { V1_0_HASHED_FIELDS, canonicalSerialize, computeDigest, payloadRecordRuleViolation, unhashedPayloadMembers, verifyEnvelope, type EvidenceEnvelope } from '@tzun/engine';
import { vectorFile } from './vectors';

type Case = Record<string, any>;
const v = vectorFile<{ cases: Case[] }>('cross-sdk-parity-vectors.json');
const row = (r: Case) => ({ outcome: r.outcome, ...(r.reason !== undefined && { reason: r.reason }) });

describe('cross-SDK parity vectors', () => {
  it.each(v.cases)('$case', (c) => {
    const payload = JSON.parse(c.json);
    const canonical = canonicalSerialize(payload, [...V1_0_HASHED_FIELDS]);
    expect(canonical).toBe(c.canonical);
    expect(canonical).toContain(c.contains);
    expect(computeDigest(canonical)).toBe(c.digest);
    const w = payloadRecordRuleViolation(payload);
    expect(w && { rule: w.rule, code: w.code }).toEqual(c.writer);
    expect(unhashedPayloadMembers(payload)).toEqual(c.unhashedPayloadMembers);
    const result = verifyEnvelope({ envelopeVersion: 'e1', payload, integrity: { canonicalDigest: c.digest, chainLink: null }, nonRepudiation: {}, custodyChain: [] } as unknown as EvidenceEnvelope);
    expect(result.verified).toBe(true);
    expect({
      decider: row(result.decider!),
      contributions: row(result.contributions!),
      links: row(result.links!),
      signoffExpectation: { valid: result.signoffExpectationValid, ...(result.signoffExpectationReason !== undefined && { reason: result.signoffExpectationReason }) },
    }).toEqual(c.rows);
  });
});
