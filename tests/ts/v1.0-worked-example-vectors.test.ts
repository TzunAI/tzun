/**
 * vectors/v1.0-worked-example-vectors.json against the engine: every
 * canonical byte string and digest in the file is what the
 * engine computes, and every record reads as the design says. The Python
 * recomputation is tests/cross-sdk/test_v1_0_worked_example_vectors.py.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  SchemaRegistry,
  agentDescriptorDigest,
  assertionDigest,
  canonicalSerialize,
  canonicalSerializeAgentDescriptor,
  checkMandateIssuance,
  computeDigest,
  deciderCommitment,
  deciderCommitmentSalt,
  mandateConfirmationChallenge,
  mandateDigest,
  mandateEventBodyDigest,
  mandateStatementChallenge,
  mandateStatementDigest,
  outputDigest,
  stepDigest,
  verifyEnvelope,
  verifyDeciderOpening,
} from '@tzun/engine';

const file = JSON.parse(readFileSync(join(__dirname, '..', '..', 'vectors', 'v1.0-worked-example-vectors.json'), 'utf8'));
const records: [string, any][] = file.records.map((r: { id: string }) => [r.id, r]);
const record = (id: string) => file.records.find((r: { id: string }) => r.id === id);
const envelope = (r: any, nonRepudiation: Record<string, unknown> = {}) =>
  ({
    envelopeVersion: 'e1', payload: r.payload, integrity: { canonicalDigest: r.digest, chainLink: null },
    nonRepudiation, custodyChain: [], attestationStatus: 'none',
  }) as never;

describe('v1.0 worked-example vectors (W1–W7)', () => {
  it('names the v1.0 hashed field set: eleven names', () => {
    expect(file.hashedFieldSet).toEqual(new SchemaRegistry().get('v1.0')!.hashedFieldSet);
    expect(file.hashedFieldSet).toHaveLength(11);
  });

  it.each(records)('record %s', (_id, r) => {
    const canonical = canonicalSerialize(r.payload, file.hashedFieldSet);
    expect(canonical).toBe(r.canonical);
    expect(Buffer.byteLength(canonical)).toBe(r.byteLength);
    expect(computeDigest(canonical)).toBe(r.digest);
    const result = verifyEnvelope(envelope(r));
    expect([result.schemaValid, result.recomputedDigest]).toEqual([true, r.digest]);
  });

  it('reads each record as the design says, from the record alone', () => {
    const w1 = verifyEnvelope(envelope(record('W1')));
    expect(w1.decider).toMatchObject({ outcome: 'checked-correct', kind: 'agent' });
    expect(w1.contributions).toMatchObject({ outcome: 'checked-correct', decidingStep: 'record' });
    // W1r is W1 relabelled: its payload no longer hashes to W1's stored digest.
    const relabelled = verifyEnvelope(envelope({ ...record('W1r'), digest: record('W1').digest }));
    expect(relabelled.decider?.reason).toBe('digest_invalid');
    expect(verifyEnvelope(envelope(record('W2'))).contributions).toMatchObject({ outcome: 'checked-correct', binding: { outcome: 'checked-correct' } });
    const w3 = verifyEnvelope(envelope(record('W3')));
    expect(w3.links).toMatchObject({ outcome: 'checked-correct', relationNames: ['derivedFrom', 'root'] });
    expect(w3.contributions?.binding).toMatchObject({ outcome: 'checked-correct', approvals: [1] });
    expect(verifyEnvelope(envelope(record('W3s'))).contributions?.binding).toMatchObject({ reason: 'decided_output_differs' });
    const statement = file.mandateStatements[0].statement;
    const block = { statement, assertion: file.mandateAssertions[0].assertion, assertionTimestamp: null, document: file.mandateDocuments[0].document };
    expect(checkMandateIssuance(envelope(record('W5'), { mandateIssuance: block }))).toEqual({ outcome: 'checked-correct', valid: true });
    const w6 = verifyEnvelope(envelope(record('W6'), { mandate: block }));
    expect([w6.signoffExpectationValid, w6.mandate?.scope?.outcome, w6.mandate?.limits?.outcome]).toEqual([true, 'checked-correct', 'checked-correct']);
    expect(w6.links?.relations[0]).toMatchObject({ rel: 'mandate', outcome: 'not-checked', reason: 'not_in_bundle:link_target' });
    const w7 = verifyEnvelope(envelope(record('W7')));
    expect(w7.links?.relations.map((x) => [x.rel, x.outcome])).toEqual([['appeals', 'checked-correct'], ['subject', 'checked-correct']]);
  });

  it('output and step digests', () => {
    for (const o of file.outputDigests) expect(outputDigest(o.value)).toBe(o.digest);
    for (const s of file.stepDigests) expect(stepDigest(s.step)).toBe(s.digest);
  });

  it('agent descriptors', () => {
    for (const d of file.agentDescriptors) {
      expect(canonicalSerializeAgentDescriptor(d.descriptor)).toBe(d.canonical);
      expect(agentDescriptorDigest(d.descriptor)).toBe(d.digest);
    }
  });

  it('decider commitments, by bytes and by base64url salt, their openings, and a derived salt', () => {
    for (const c of file.deciderCommitments) {
      expect(deciderCommitment(c.innerId, Buffer.from(c.saltHex, 'hex'))).toBe(c.commitment);
      expect(deciderCommitment(c.innerId, c.saltBase64url)).toBe(c.commitment);
      expect(verifyDeciderOpening(c.commitment, { salt: c.saltBase64url, id: c.innerId })).toBe(true);
    }
    for (const d of file.derivedSalts) {
      expect(deciderCommitmentSalt(Buffer.from(d.secretHex, 'hex'), d.idempotencyKey, d.innerId)).toBe(d.saltBase64url);
      expect(deciderCommitment(d.innerId, d.saltBase64url)).toBe(d.commitment);
    }
  });

  it('mandate document, statement, assertion, event bodies, and the confirmation challenge', () => {
    for (const d of file.mandateDocuments) expect(mandateDigest(d.document)).toBe(d.digest);
    for (const s of file.mandateStatements) {
      expect(mandateStatementDigest(s.statement)).toBe(s.digest);
      expect(mandateStatementChallenge(s.digest)).toBe(s.challenge);
    }
    for (const a of file.mandateAssertions) expect(assertionDigest(a.assertion)).toBe(a.digest);
    for (const e of file.mandateEventBodies) {
      expect(mandateEventBodyDigest(e.body)).toBe(e.digest);
      expect(e).not.toHaveProperty('leaf');
    }
    for (const c of file.confirmationChallenges) expect(mandateConfirmationChallenge(c.digest)).toBe(c.challenge);
  });

  it('assertion digests', () => {
    for (const a of file.assertionDigests) expect([a.label, assertionDigest(a.assertion)]).toEqual([a.label, a.digest]);
  });
});
