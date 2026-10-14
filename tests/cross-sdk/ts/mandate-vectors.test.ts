/**
 * vectors/mandate-vectors.json (Record §9.6 to §9.11): the engine gives every
 * answer the file states. The Python half is tests/cross-sdk/test_mandate_vectors.py.
 */
import {
  assertionDigest,
  buildMandateEventBody,
  checkMandateConsumption,
  checkMandateIssuance,
  checkMandateLimits,
  evaluateMandateScope,
  evaluatePredicate,
  mandateConfirmationViolation,
  mandateDigest,
  mandateDocumentViolation,
  mandateEventBodyDigest,
  mandateExpiredAt,
  mandateStatementChallenge,
  mandateStatementDigest,
  mandateStatementViolation,
  planMandateClaim,
  predecessorPrincipalViolation,
  predicateViolation,
  revocationInstantViolation,
} from '@tzun/engine';
import { codeOf, vectorFile } from './vectors';

type Case = Record<string, any>;
const v = vectorFile<Record<string, any>>('mandate-vectors.json');
const W5_TARGET = (claims: Case[]) => claims[0].expect.links.find((l: Case) => l.rel === 'mandate').target;

describe('mandate vectors', () => {
  it.each(v.documents as Case[])('document: $case', (c) => {
    expect(codeOf(mandateDocumentViolation(c.document, c.prepare === false ? { prepare: false } : {}))).toEqual(c.violation);
    if (c.violation === null) expect(mandateDigest(c.document)).toBe(c.digest);
  });
  it.each(v.statements as Case[])('statement: $case', (c) => {
    expect(mandateStatementViolation(c.statement) === null).toBe(c.wellFormed);
    expect(mandateStatementDigest(c.statement)).toBe(c.digest);
    if (c.digest !== null) expect(mandateStatementChallenge(c.digest)).toBe(c.challenge);
  });
  it.each(v.assertionDigests as Case[])('assertion digest: $case', (c) => expect(assertionDigest(c.assertion)).toBe(c.digest));
  it.each(v.predicates as Case[])('predicate: $case', (c) => {
    expect(predicateViolation(c.predicate) === null).toBe(c.wellFormed);
    expect(evaluatePredicate(c.predicate, c.payloadJson !== undefined ? JSON.parse(c.payloadJson) : c.payload)).toBe(c.outcome);
  });
  it.each(v.scope as Case[])('scope: $case', (c) => expect(evaluateMandateScope(c.document, c.payload)).toEqual(c.expect));
  it.each(v.limits as Case[])('limits: $case', (c) => expect(checkMandateLimits(c.document, c.payload)).toEqual(c.expect));
  it.each(v.consumption as Case[])('consumption: $case', (c) => {
    expect(checkMandateConsumption(v.documents[0].document, c.envelopes, c.lastEvent ? { lastEvent: c.lastEvent } : {})).toEqual(c.expect);
  });
  it.each(v.issuance as Case[])('issuance: $case', (c) => expect(checkMandateIssuance(c.envelope)).toEqual(c.expect));
  it.each(v.eventBodies as Case[])('event body: $case', (c) => {
    expect(mandateEventBodyDigest(c.body)).toBe(c.digest);
    expect(c).not.toHaveProperty('leaf');
  });
  it.each(v.eventWriterRefusals as Case[])('event body refused by a writer: $case', (c) => expect(() => buildMandateEventBody(c.parts)).toThrow());
  it.each(v.claims as Case[])('claim: $case', (c) => {
    const { message: _message, ...plan } = planMandateClaim({
      document: c.document, mandate: c.mandate, payload: c.payload, assertionDigest: v.assertionDigests[0].digest, issuance: W5_TARGET(v.claims),
    }) as Case;
    expect(plan).toEqual(c.expect);
  });
  it.each(v.lifecycle.revocationInstants as Case[])('revocation instant: $case', (c) =>
    expect(revocationInstantViolation(c.claimedRevocationInstant, c.capturedAt) !== null).toBe(c.refused));
  it.each(v.lifecycle.successors as Case[])('successor: $case', (c) => expect(predecessorPrincipalViolation(c.document, c.predecessor) !== null).toBe(c.refused));
  it.each(v.lifecycle.confirmations as Case[])('confirmation: $case', (c) => expect(mandateConfirmationViolation(c.envelope)?.code ?? null).toBe(c.refused));
  it.each(v.lifecycle.expiry as Case[])('expiry: $case', (c) => expect(mandateExpiredAt(c.notAfter, c.instant)).toBe(c.expired));
});
