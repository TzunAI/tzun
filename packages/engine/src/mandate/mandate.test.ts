import {
  P256_ORDER,
  assertionDigest,
  assertionDigestResult,
  buildMandateEventBody,
  buildMandateStatement,
  checkMandateConsumption,
  checkMandateIssuance,
  checkMandateLimits,
  deciderInMandate,
  evaluateMandateConfirm,
  evaluateMandateScope,
  evaluatePredicate,
  globMatch,
  mandateBlockViolation,
  mandateConfirmationChallenge,
  mandateConfirmationViolation,
  mandateDigest,
  mandateDocumentViolation,
  mandateEventBodyDigest,
  mandateEventBodyViolation,
  mandateExpiredAt,
  mandateIssuanceInput,
  mandateRevocationInput,
  mandateStatementChallenge,
  mandateStatementDigest,
  mandateStatementViolation,
  planMandateClaim,
  predecessorPrincipalViolation,
  predicateViolation,
  revocationInstantViolation,
} from './index';
import { checkSignoffExpectation, describeSignoffExpectationViolation, signoffExpectationViolation } from '../signoff-expectation';
import { assembleEnvelope } from '../envelope';
import { checkLinks } from '../links';
import { verifyEnvelope } from '../verify';
import type { EvidenceEnvelope, WebauthnAssertion } from '../types/evidence';
import type { MandateDocument, MandateStatement } from '../types/mandate';

const AGENT = 'sha256:eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f';
const MODEL = 'sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947';
/** Worked example W4: the mandate document, 921 canonical bytes. */
const W4_DOCUMENT =
  '{"agents":["desc:sha256:eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f"],"confirm":{"fraud":{"op":"eq","path":"/aiOutput/fraudFlag","quant":null,"value":true}},"delegation":{"allowed":false,"attenuation":"subset","maxDepth":0},"limits":{"cumulative":{"paid":{"max":250000000,"path":"/aiOutput/amountMinor"}},"maxRecords":10000},"mandateId":"6b1f0e2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b","parent":null,"policyDigest":null,"predecessor":null,"principal":{"credential":null,"signer":"user-2c9d"},"review":{"maxAgeMs":604800000},"schemaVersion":"v1.0","scope":{"actions":["approve","refer"],"aiSystemIds":["claims-triage-v4"],"models":["sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947"],"predicates":{"cap":{"op":"le","path":"/aiOutput/amountMinor","quant":null,"value":500000}}},"v":"tzun-mandate/1","validity":{"notAfter":"2026-12-31T23:59:59.999Z","notBefore":"2026-10-01T00:00:00.000Z"}}';
/** W4's statement: no signerName, policyDigest none. */
const W4_STATEMENT =
  '{"mandateDigest":"26b1fbef903914e39cb45378b7f10648611c751c1b93624173bcfe7b7b9938da","meaning":"responsibility","mode":"mandate","notBefore":"eip155:1@23400000:0x9709713cdb609ef086959f42eb4a56159cb9ac637e3f32fb381796e68b2c7efb","policyDigest":"none","signer":"user-2c9d","signerKind":"human","v":"tzun-signoff-mandate/1"}';
/** W4's assertion: Ed25519 over the statement challenge, with the RFC 8037 Appendix A key. */
const W4_ASSERTION: WebauthnAssertion = {
  signature: 'QiEu8ZU71lvqBrWt2VOZ-kvFyd4HwtGEQ-h6yE6ndP9DQ2QZC7UqUTwwgvxxIWSepOPQ5EaPcJosrVzkbKfmBA',
  credentialKeyId: 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
  algorithm: 'Ed25519',
  authenticatorData: 'Chw32mRsvW5TbBTARkVeu2ErLBpCvZeP6rZmEl_zd5UFAAAAAQ',
  clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiS1pUVTc1VXZ1NUllVnNacElwRU4xU0Rxc2tycDNyQTNEY3dsOG9NZ1VCTSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby50enVuLmFpIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ',
};
const W4_MANDATE_DIGEST = '26b1fbef903914e39cb45378b7f10648611c751c1b93624173bcfe7b7b9938da';
const W4_STATEMENT_DIGEST = '9a2e761fd633a06433c2e386fd2107112260da481db7c4c4b5795954a7e69492';
const W4_CHALLENGE = 'KZTU75Uvu5IeVsZpIpEN1SDqskrp3rA3Dcwl8oMgUBM';
const W4_ASSERTION_DIGEST = '79aafeb32c197be65d3b27c7b1cc469beff89e8650d1a84e02b437ec7937966d';
/** W5: the issuance record of W4's mandate. */
const W5_DIGEST = 'fb29b130c25c42d6ac72f1ea4123f0c542d6fefed9cfcaaa6b9a1b5e74af9844';
const W5_EVIDENCE_ID = '7a2c0d4e-1111-4a1a-8a1a-000000000001';
const CLAIMS_ORIGIN = 'test.insurer.example/9a8b7c6d5e4f30211203f4e5d6c7b8a9/evidence/636c61696d73';
const W5_TARGET = { digest: W5_DIGEST, evidenceId: W5_EVIDENCE_ID, locator: { origin: CLAIMS_ORIGIN, seq: 1 } };
const doc = () => JSON.parse(W4_DOCUMENT);
const statement = () => JSON.parse(W4_STATEMENT);

function clientData(challenge: string): string {
  return Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://rp.example' })).toString('base64url');
}

function derInteger(value: bigint, pad = 0): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let body = Buffer.from(hex, 'hex');
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
  body = Buffer.concat([Buffer.alloc(pad), body]);
  return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}
function derSignature(r: bigint, s: bigint, opts: { padR?: number; longLength?: boolean } = {}): Buffer {
  const body = Buffer.concat([derInteger(r, opts.padR ?? 0), derInteger(s)]);
  const len = opts.longLength ? Buffer.from([0x81, body.length]) : Buffer.from([body.length]);
  return Buffer.concat([Buffer.from([0x30]), len, body]);
}
const R = BigInt('0x' + '5a'.repeat(32));
const LOW_S = BigInt('0x' + '3b'.repeat(32));
const HIGH_S = P256_ORDER - LOW_S;

/** An ES256 assertion presenting `challenge`, its signature `der`. */
function es256Assertion(challenge: string, der: Buffer = derSignature(R, LOW_S)) {
  return {
    signature: der.toString('base64url'),
    credentialKeyId: 'cred-1',
    algorithm: 'ES256' as const,
    authenticatorData: Buffer.alloc(37, 7).toString('base64url'),
    clientDataJSON: clientData(challenge),
  };
}

describe('mandate document (W4, Record §9.7)', () => {
  it('reproduces W4: 921 canonical bytes and its digest, passing the restriction', () => {
    expect(mandateDocumentViolation(doc())).toBeNull();
    expect(Buffer.byteLength(W4_DOCUMENT)).toBe(921);
    expect(mandateDigest(doc())).toBe(W4_MANDATE_DIGEST);
  });

  it("admits a path into a step's bill of materials: contributions is hashed", () => {
    const d = doc();
    d.scope.predicates.temp = { op: 'le', path: '/contributions/steps/0/aiBom/inferenceParameters/temperature', quant: null, value: 1 };
    expect(mandateDocumentViolation(d)).toBeNull();
  });

  const cases: [string, (d: any) => unknown, string][] = [
    ['a missing key', (d) => { delete d.parent; return d; }, 'invalid_document'],
    ['an unsorted set', (d) => { d.scope.actions = ['refer', 'approve']; return d; }, 'invalid_document'],
    ['a fraction', (d) => { d.limits.maxRecords = 1.5; return d; }, 'invalid_document'],
    ['maxRecords 0', (d) => { d.limits.maxRecords = 0; return d; }, 'invalid_document'],
    ['a negative integer', (d) => { d.review.maxAgeMs = -1; return d; }, 'invalid_document'],
    ['a non-ASCII string', (d) => { d.scope.aiSystemIds = ['claims-tri\u00e4ge']; return d; }, 'invalid_document'],
    ['an email principal', (d) => { d.principal.signer = 'sam@example.com'; return d; }, 'invalid_principal'],
    ['a principal credential that is not a digest', (d) => { d.principal.credential = 'abc'; return d; }, 'invalid_principal'],
    ['a human agent identifier', (d) => { d.agents = ['acct:u-1']; return d; }, 'invalid_document'],
    ['an instant without milliseconds', (d) => { d.validity.notAfter = '2026-12-31T23:59:59Z'; return d; }, 'invalid_document'],
    ['a window that ends before it begins', (d) => { d.validity.notAfter = '2026-09-01T00:00:00.000Z'; return d; }, 'invalid_document'],
    ['a sub-mandate', (d) => { d.delegation.allowed = true; return d; }, 'invalid_document'],
    ['an unregistered version', (d) => { d.schemaVersion = 'v1.1'; return d; }, 'restriction_failed'],
    ['a cap reading an unhashed member', (d) => { d.limits.cumulative.paid.path = '/nonRepudiation/x'; return d; }, 'restriction_failed'],
    ['a predicate reading the moved aiBom', (d) => { d.scope.predicates.cap.path = '/aiBom/modelDescriptorDigest'; return d; }, 'restriction_failed'],
    ['a predicate with a bad escape', (d) => { d.scope.predicates.cap.path = '/aiOutput/a~2b'; return d; }, 'invalid_predicate'],
    ['eq null', (d) => { d.confirm.fraud.value = null; return d; }, 'invalid_predicate'],
    ['an empty cumulative', (d) => { d.limits.cumulative = {}; return d; }, 'empty_cumulative'],
    ['a bad cap name', (d) => { d.limits.cumulative = { 'pa id': d.limits.cumulative.paid }; return d; }, 'invalid_cap'],
    ['17 caps', (d) => {
      d.limits.cumulative = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`c${i}`, { path: '/aiOutput/amountMinor', max: 1 }]));
      return d;
    }, 'invalid_cap'],
    ['a document over 16 KiB', (d) => {
      d.scope.aiSystemIds = Array.from({ length: 700 }, (_, i) => `system-${String(i).padStart(4, '0')}-xxxxxxxxxx`);
      return d;
    }, 'document_too_large'],
  ];
  it.each(cases)('refuses %s', (_name, mutate, code) => {
    expect(mandateDocumentViolation(mutate(doc()))?.code).toBe(code);
  });

  it('reads a document the 0.8.0 writer would refuse when prepare is off', () => {
    const d = doc();
    d.delegation = { allowed: true, maxDepth: 1, attenuation: 'subset' };
    expect(mandateDocumentViolation(d, { prepare: false })).toBeNull();
  });
});

describe('mandate statement (W4, Record §9.6)', () => {
  it('reproduces the statement digest and challenge', () => {
    const digest = mandateStatementDigest(statement());
    expect(digest).toBe(W4_STATEMENT_DIGEST);
    expect(mandateStatementChallenge(digest!)).toBe(W4_CHALLENGE);
  });

  it('builds the same statement from its parts, with no printed name', () => {
    expect(
      buildMandateStatement({
        mandateDigest: W4_MANDATE_DIGEST,
        signer: 'user-2c9d',
        policyDigest: null,
        notBefore: 'eip155:1@23400000:0x9709713cdb609ef086959f42eb4a56159cb9ac637e3f32fb381796e68b2c7efb',
      }),
    ).toEqual(statement());
  });

  it.each([
    ['a statement carrying signerName', { signerName: 'U2FtIFByaW5jaXBhbA' }],
    ['another mode', { mode: 'batch' }],
    ['an agent signer kind', { signerKind: 'agent' }],
    ['an email signer', { signer: 'sam@example.com' }],
    ['a bad notBefore', { notBefore: 'eip155:01@1:0x' + '00'.repeat(32) }],
    ['an extra key', { extra: 'x' }],
  ])('refuses %s', (_name, change) => {
    expect(mandateStatementViolation({ ...statement(), ...change })).not.toBeNull();
    expect(mandateStatementDigest({ ...statement(), ...change })).toBeNull();
  });
});

describe('assertion digest', () => {
  const challenge = W4_CHALLENGE;

  it("reproduces W4's Ed25519 assertion digest", () => {
    expect(assertionDigest(W4_ASSERTION)).toBe(W4_ASSERTION_DIGEST);
  });

  it('gives one digest for the low-S, high-S and non-minimal DER encodings of one ES256 signature', () => {
    const low = assertionDigest(es256Assertion(challenge, derSignature(R, LOW_S)));
    expect(low).toMatch(/^[0-9a-f]{64}$/);
    expect(assertionDigest(es256Assertion(challenge, derSignature(R, HIGH_S)))).toBe(low);
    expect(assertionDigest(es256Assertion(challenge, derSignature(R, LOW_S, { padR: 2 })))).toBe(low);
    expect(assertionDigest(es256Assertion(challenge, derSignature(R, LOW_S, { longLength: true })))).toBe(low);
  });

  it('reads base64 and base64url alike', () => {
    const a = es256Assertion(challenge);
    const b = { ...a, signature: Buffer.from(a.signature, 'base64url').toString('base64') };
    expect(assertionDigest(b)).toBe(assertionDigest(a));
  });

  it('refuses a signature that is not DER, and raw r||s', () => {
    const raw = Buffer.concat([Buffer.alloc(32, 0x5a), Buffer.alloc(32, 0x3b)]);
    expect(assertionDigestResult(es256Assertion(challenge, raw))).toEqual({ ok: false, reason: 'signature_not_der' });
    expect(assertionDigestResult(es256Assertion(challenge, Buffer.from('not der')))).toEqual({ ok: false, reason: 'signature_not_der' });
    expect(assertionDigestResult(es256Assertion(challenge, derSignature(R, P256_ORDER)))).toEqual({ ok: false, reason: 'signature_not_der' });
    const trailing = Buffer.concat([derSignature(R, LOW_S), Buffer.from([0])]);
    expect(assertionDigestResult(es256Assertion(challenge, trailing))).toEqual({ ok: false, reason: 'signature_not_der' });
  });

  it('hashes an Ed25519 signature as given, and refuses missing data or another algorithm', () => {
    const ed = { ...es256Assertion(challenge), algorithm: 'Ed25519' as const, signature: Buffer.alloc(64, 9).toString('base64url') };
    expect(assertionDigest(ed)).toMatch(/^[0-9a-f]{64}$/);
    expect(assertionDigestResult({ ...ed, clientDataJSON: undefined })).toEqual({ ok: false, reason: 'missing_client_data' });
    expect(assertionDigestResult({ ...ed, algorithm: 'RS256' })).toEqual({ ok: false, reason: 'unsupported_algorithm' });
    expect(assertionDigestResult({ ...ed, signature: 'a===' })).toEqual({ ok: false, reason: 'invalid_encoding' });
  });
});

describe('predicates', () => {
  const payload = {
    aiOutput: {
      amount: 120000, flag: false, label: 'claims/eu/fast', tags: ['a', 'b'], counts: [1, 2, 3], empty: [],
      nested: { 'a/b': 1, 'c~d': 2 }, nil: null, big: 2 ** 53, frac: 1.5, astral: '😀/x', one: 1,
    },
  };
  const p = (path: string, op: string, value: unknown, quant: unknown = null) => evaluatePredicate({ path, op, value, quant }, payload);

  it.each([
    ['eq integer', p('/aiOutput/amount', 'eq', 120000), 'true'],
    ['ne integer', p('/aiOutput/amount', 'ne', 120000), 'false'],
    ['eq type mismatch is false', p('/aiOutput/amount', 'eq', '120000'), 'false'],
    ['1 is not true', p('/aiOutput/one', 'eq', true), 'false'],
    ['false eq false', p('/aiOutput/flag', 'eq', false), 'true'],
    ['le', p('/aiOutput/amount', 'le', 500000), 'true'],
    ['gt', p('/aiOutput/amount', 'gt', 500000), 'false'],
    ['lt on a string', p('/aiOutput/label', 'lt', 5), 'undeterminable'],
    ['a fraction is not an integer', p('/aiOutput/frac', 'ge', 1), 'undeterminable'],
    ['2^53 is not an integer', p('/aiOutput/big', 'ge', 1), 'undeterminable'],
    ['in', p('/aiOutput/label', 'in', ['claims/eu/fast', 'x']), 'true'],
    ['notIn', p('/aiOutput/label', 'notIn', ['x']), 'true'],
    ['prefix', p('/aiOutput/label', 'prefix', 'claims/'), 'true'],
    ['glob *', p('/aiOutput/label', 'glob', ['claims/*/fast']), 'true'],
    ['glob * does not cross /', p('/aiOutput/label', 'glob', ['claims/*']), 'false'],
    ['glob **', p('/aiOutput/label', 'glob', ['claims/**']), 'true'],
    ['glob ** matches zero segments in the middle', p('/aiOutput/label', 'glob', ['claims/**/eu/fast']), 'true'],
    ['glob ** matches zero segments at the end', p('/aiOutput/label', 'glob', ['claims/eu/fast/**']), 'true'],
    ['glob ? over an astral code point', p('/aiOutput/astral', 'glob', ['?/x']), 'true'],
    ['missing path', p('/aiOutput/none', 'eq', 1), 'undeterminable'],
    ['null subject', p('/aiOutput/nil', 'eq', 1), 'undeterminable'],
    ['escaped tokens', p('/aiOutput/nested/a~1b', 'eq', 1), 'true'],
    ['escaped tilde', p('/aiOutput/nested/c~0d', 'eq', 2), 'true'],
    ['array index', p('/aiOutput/counts/2', 'eq', 3), 'true'],
    ['array index 01 resolves to nothing', p('/aiOutput/counts/01', 'eq', 2), 'undeterminable'],
    ['array index - resolves to nothing', p('/aiOutput/counts/-', 'eq', 3), 'undeterminable'],
    ['all', p('/aiOutput/counts', 'le', 3, 'all'), 'true'],
    ['all with one false', p('/aiOutput/counts', 'le', 2, 'all'), 'false'],
    ['any', p('/aiOutput/counts', 'eq', 2, 'any'), 'true'],
    ['all over [] is true', p('/aiOutput/empty', 'eq', 1, 'all'), 'true'],
    ['any over [] is false', p('/aiOutput/empty', 'eq', 1, 'any'), 'false'],
    ['quant on a scalar', p('/aiOutput/amount', 'eq', 1, 'all'), 'undeterminable'],
    ['no quant on an array', p('/aiOutput/tags', 'eq', 'a'), 'undeterminable'],
    ['a malformed predicate', evaluatePredicate({ path: 'aiOutput', op: 'eq', value: 1, quant: null }, payload), 'undeterminable'],
  ])('%s', (_name, outcome, expected) => {
    expect(outcome).toBe(expected);
  });

  it('is undeterminable past the subject limits', () => {
    const long = { aiOutput: { s: 'x'.repeat(4097), arr: Array(10001).fill(1) } };
    expect(evaluatePredicate({ path: '/aiOutput/s', op: 'prefix', value: 'x', quant: null }, long)).toBe('undeterminable');
    expect(evaluatePredicate({ path: '/aiOutput/arr', op: 'eq', value: 1, quant: 'all' }, long)).toBe('undeterminable');
  });

  it('matches ** against zero whole segments', () => {
    expect(globMatch('a/**/b', 'a/b')).toBe(true);
    expect(globMatch('a/**', 'a')).toBe(true);
    expect(globMatch('**', '')).toBe(true);
    expect(globMatch('a/**/b', 'a/x/y/b')).toBe(true);
    expect(globMatch('a/**/b', 'a/x/c')).toBe(false);
  });

  it('matches a pathological glob within the limits without backtracking blow-up', () => {
    const pattern = '*a'.repeat(127) + 'b';
    const subject = 'a'.repeat(4096);
    const started = Date.now();
    expect(globMatch(pattern, subject)).toBe(false);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('refuses ill-formed predicates at prepare', () => {
    expect(predicateViolation({ path: '/a', op: 'in', value: ['b', 'a'], quant: null })).not.toBeNull();
    expect(predicateViolation({ path: '/a', op: 'glob', value: ['x'.repeat(257)], quant: null })).not.toBeNull();
    expect(predicateViolation({ path: '/a', op: 'lt', value: -1, quant: null })).not.toBeNull();
    expect(predicateViolation({ path: '/a', op: 'eq', value: 'x', quant: 'some' })).not.toBeNull();
    expect(predicateViolation({ path: '/a', op: 'eq', value: true, quant: null })).toBeNull();
  });
});

/** The steps of a record whose one model is `model`, proposed by the mandated agent. */
function proposeStep(aiOutput: Record<string, unknown>, model = MODEL) {
  return {
    role: 'propose',
    actor: { kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT },
    aiBom: { modelDescriptorDigest: model, vendorFingerprint: null, promptTemplate: null, inferenceParameters: null, infrastructure: null },
    inputs: [],
    output: 'sha256:' + '25'.repeat(32),
    verdict: null,
    reason: null,
    prev: null,
  };
}

/** A mandated record (slot 41) under W4's mandate: W6's terms. */
function mandatedPayload(over: Record<string, unknown> = {}) {
  const aiOutput = (over.aiOutput as Record<string, unknown>) ?? { amountMinor: 120000, fraudFlag: false, recommendation: 'approve' };
  return {
    schemaVersion: 'v1.0',
    aiSystemId: 'claims-triage-v4',
    action: 'approve',
    reason: 'Policy active; invoice matches the repair estimate',
    aiOutput,
    decider: { kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null },
    contributions: { pipeline: null, externals: [], steps: [proposeStep(aiOutput)] },
    links: [{ rel: 'mandate', target: W5_TARGET, attrs: null }],
    signoffExpectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm: false },
    capturedAt: '2026-11-20T10:14:50.000Z',
    ...over,
  };
}

describe('scope, confirmation and limits', () => {
  it("reads W6's terms within scope and within limits", () => {
    expect(evaluateMandateScope(doc(), mandatedPayload())).toEqual({
      verdict: 'within', failures: [], undeterminable: [], agentInMandate: true, confirmationEvaded: false,
    });
    expect(checkMandateLimits(doc(), mandatedPayload())).toEqual({ valid: true, slot: 41, totals: { paid: 5230000 } });
  });

  it('reports each failed constraint, a model outside scope in any step, and an undeterminable predicate', () => {
    const out = evaluateMandateScope(doc(), mandatedPayload({ action: 'deny', aiOutput: { amountMinor: 600000, fraudFlag: false } }));
    expect(out.verdict).toBe('outside');
    expect(out.failures).toEqual([{ constraint: 'actions' }, { constraint: 'predicate', name: 'cap' }]);
    // A model outside scope may not review either.
    const reviewed = mandatedPayload();
    (reviewed.contributions.steps as unknown[]).push({ ...proposeStep({}, 'sha256:' + '99'.repeat(32)), role: 'review', verdict: 'approve' });
    expect(evaluateMandateScope(doc(), reviewed).failures).toEqual([{ constraint: 'models' }]);
    // A model set while no step records a model.
    const noModel = mandatedPayload({ contributions: null });
    expect(evaluateMandateScope(doc(), noModel).undeterminable).toEqual([{ constraint: 'models' }]);
    expect(evaluateMandateScope(doc(), mandatedPayload({ aiOutput: { fraudFlag: false } })).verdict).toBe('undeterminable');
    expect(
      evaluateMandateScope(doc(), mandatedPayload({ decider: { kind: 'agent-mandated', id: 'spiffe://x.example/y', agent: 'sha256:' + '11'.repeat(32) } }))
        .agentInMandate,
    ).toBe(false);
  });

  it('reads a path into the moved aiBom as undeterminable, never within', () => {
    const d = doc();
    d.scope.predicates.model = { op: 'eq', path: '/aiBom/modelDescriptorDigest', quant: null, value: MODEL };
    expect(evaluateMandateScope(d, mandatedPayload()).undeterminable).toContainEqual({ constraint: 'restriction' });
  });

  it('names a decider by its id, by desc: and its agent, or by the same cmt', () => {
    expect(deciderInMandate({ kind: 'agent-mandated', id: 'spiffe://claims.example/agent', agent: AGENT }, [`desc:${AGENT}`])).toBe(true);
    expect(deciderInMandate({ kind: 'agent-mandated', id: 'spiffe://claims.example/agent', agent: AGENT }, ['spiffe://claims.example/agent'])).toBe(true);
    const cmt = 'cmt:' + 'ab'.repeat(32);
    expect(deciderInMandate({ kind: 'agent-mandated', id: cmt, agent: 'sha256:' + '11'.repeat(32) }, [cmt])).toBe(true);
    expect(deciderInMandate({ kind: 'agent-mandated', id: 'spiffe://claims.example/agent', agent: 'sha256:' + '11'.repeat(32) }, [`desc:${AGENT}`])).toBe(false);
  });

  it('reads a record that owes no confirmation, while a confirm predicate is undeterminable, as undeterminable', () => {
    const silent = mandatedPayload({ aiOutput: { amountMinor: 120000 } });
    expect(evaluateMandateConfirm(doc(), silent).confirm).toBeNull();
    expect(evaluateMandateScope(doc(), silent)).toEqual({
      verdict: 'undeterminable', failures: [], undeterminable: [{ constraint: 'confirm', name: 'fraud' }],
      agentInMandate: true, confirmationEvaded: false,
    });
    const owed = mandatedPayload({
      aiOutput: { amountMinor: 120000 },
      signoffExpectation: { ...mandatedPayload().signoffExpectation, confirm: true },
    });
    expect(evaluateMandateScope(doc(), owed).verdict).toBe('within');
  });

  it('flags a confirmation evaded, and computes the flag a capture writes', () => {
    const fraud = mandatedPayload({ aiOutput: { amountMinor: 1, fraudFlag: true } });
    expect(evaluateMandateScope(doc(), fraud).confirmationEvaded).toBe(true);
    expect(evaluateMandateConfirm(doc(), fraud)).toEqual({ confirm: true, holding: ['fraud'], undeterminable: [] });
    expect(evaluateMandateConfirm(doc(), mandatedPayload())).toEqual({ confirm: false, holding: [], undeterminable: [] });
    expect(evaluateMandateConfirm(doc(), mandatedPayload({ aiOutput: { amountMinor: 1 } })).confirm).toBeNull();
  });

  it('reports malformed totals and exceeded limits', () => {
    const exp = (e: Record<string, unknown>) => mandatedPayload({ signoffExpectation: { ...mandatedPayload().signoffExpectation, ...e } });
    expect(checkMandateLimits(doc(), exp({ totals: null })).reason).toBe('mandate_totals_malformed');
    expect(checkMandateLimits(doc(), exp({ totals: { paid: 1, other: 1 } })).reason).toBe('mandate_totals_malformed');
    expect(checkMandateLimits(doc(), exp({ totals: { paid: 100 } })).reason).toBe('mandate_limit_exceeded');
    expect(checkMandateLimits(doc(), exp({ totals: { paid: 250000001 } })).reason).toBe('mandate_limit_exceeded');
    expect(checkMandateLimits(doc(), exp({ mandateSeq: 10001 })).reason).toBe('mandate_limit_exceeded');
    expect(checkMandateLimits(doc(), mandatedPayload({ aiOutput: { amountMinor: '3' } })).reason).toBe('mandate_totals_malformed');
  });
});

describe('consumption over records (Record §9.10)', () => {
  const rec = (slot: number, amount: number, total: number) => ({
    payload: mandatedPayload({
      aiOutput: { amountMinor: amount, fraudFlag: false },
      signoffExpectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: slot, totals: { paid: total }, confirm: false },
    }),
  });
  const r1 = rec(1, 100, 100);
  const r2 = rec(2, 50, 150);
  const r3 = rec(3, 25, 175);

  it('holds a contiguous, explained run', () => {
    expect(checkMandateConsumption(doc(), [r3, r1, r2])).toEqual({
      duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 3, beyondEvent: [], complete: null,
    });
  });

  it('reports a withheld record as a gap with its unexplained amount (R41 to R43 with R42 withheld)', () => {
    const r41 = rec(41, 120000, 5230000);
    const r43 = rec(43, 75000, 5785000);
    const out = checkMandateConsumption(doc(), [r41, r43]);
    expect(out.gaps).toEqual([
      { from: 1, to: 40, unexplained: { paid: 5230000 - 120000 } },
      { from: 42, to: 42, unexplained: { paid: 480000 } },
    ]);
  });

  it('reports a duplicate slot, an unexplained step, and completeness against the revoked event body', () => {
    expect(checkMandateConsumption(doc(), [r1, r2, rec(2, 50, 150)]).duplicateSlots).toEqual([2]);
    expect(checkMandateConsumption(doc(), [r1, rec(2, 50, 999)]).unexplainedSteps).toEqual([
      { slot: 2, cap: 'paid', expected: 150, actual: 999 },
    ]);
    const revoked = { event: 'revoked', used: 3, totals: { paid: 175 } };
    expect(checkMandateConsumption(doc(), [r1, r2, r3], { lastEvent: revoked }).complete).toBe(true);
    expect(checkMandateConsumption(doc(), [r1, r2], { lastEvent: revoked }).complete).toBe(false);
    // Every slot is present, but the event's totals are not the last record's.
    expect(checkMandateConsumption(doc(), [r1, r2], { lastEvent: { event: 'revoked', used: 2, totals: { paid: 151 } } }).complete).toBe(false);
    expect(checkMandateConsumption(doc(), [r1, r2], { lastEvent: { event: 'revoked', used: 2, totals: { paid: 150 } } }).complete).toBe(true);
  });

  it('is not complete when a record holds a slot above the terminal event', () => {
    // Slots 1 to 3 explained, but the revocation recorded used 2: slot 3 was
    // captured after it, or the event is stale.
    const out = checkMandateConsumption(doc(), [r1, r2, r3], { lastEvent: { event: 'revoked', used: 2, totals: { paid: 150 } } });
    expect(out).toMatchObject({ gaps: [], unexplainedSteps: [], completeUpTo: 3, beyondEvent: [3], complete: false });
    const none = checkMandateConsumption(doc(), [r1, r2, r3], { lastEvent: { event: 'expired', used: 0, totals: { paid: 0 } } });
    expect(none).toMatchObject({ beyondEvent: [1, 2, 3], complete: false });
    expect(checkMandateConsumption(doc(), [r1, r2, r3]).beyondEvent).toEqual([]);
  });
});

describe('event bodies and their digests (W5)', () => {
  const issued = {
    v: 'tzun-mandate-event/1', event: 'issued', mandateDigest: W4_MANDATE_DIGEST, record: W5_DIGEST,
    successor: null, totals: null, used: null,
  };

  it("reproduces W5's issued event body and its digest", () => {
    expect(mandateEventBodyDigest(issued)).toBe('82511c5907fe6cc93c23b40b0933d4576ea86af28700eddbadae0856ece9b7b3');
    expect(buildMandateEventBody({ event: 'issued', mandateDigest: W4_MANDATE_DIGEST, record: W5_DIGEST })).toEqual(issued);
  });

  it('builds one body per state change, and refuses one that mixes them', () => {
    const revoked = buildMandateEventBody({ event: 'revoked', mandateDigest: W4_MANDATE_DIGEST, record: 'ab'.repeat(32), used: 43, totals: { paid: 5785000 } });
    expect(revoked).toMatchObject({ event: 'revoked', successor: null, used: 43 });
    expect(mandateEventBodyDigest(revoked)).toMatch(/^[0-9a-f]{64}$/);
    const superseded = buildMandateEventBody({
      event: 'superseded', mandateDigest: W4_MANDATE_DIGEST, record: 'cd'.repeat(32), successor: 'ef'.repeat(32), used: 43, totals: { paid: 5785000 },
    });
    expect(superseded.successor).toBe('ef'.repeat(32));
    const expired = buildMandateEventBody({ event: 'expired', mandateDigest: W4_MANDATE_DIGEST, record: W5_DIGEST, used: 43, totals: { paid: 5785000 } });
    expect(expired.record).toBe(W5_DIGEST);
    expect(() => buildMandateEventBody({ event: 'superseded', mandateDigest: W4_MANDATE_DIGEST, record: 'cd'.repeat(32), used: 1 })).toThrow(/successor/);
    expect(() => buildMandateEventBody({ event: 'revoked', mandateDigest: W4_MANDATE_DIGEST, record: 'cd'.repeat(32) })).toThrow(/used/);
    expect(() => buildMandateEventBody({ event: 'issued', mandateDigest: W4_MANDATE_DIGEST, record: 'cd'.repeat(32), used: 0 })).toThrow(/used/);
  });

  it('refuses a malformed body', () => {
    expect(mandateEventBodyViolation({ ...issued, event: 'paused' })).not.toBeNull();
    expect(mandateEventBodyDigest({ ...issued, used: -1 })).toBeNull();
  });
});

describe('the mandate form against its block (Verification §5)', () => {
  const block = () => ({ statement: statement(), assertion: W4_ASSERTION, assertionTimestamp: null, document: doc() });
  const envelope = (expectation: Record<string, unknown>, nonRepudiation: Record<string, unknown>, recordDigest = 'ab'.repeat(32)) => ({
    payload: { ...mandatedPayload({ signoffExpectation: expectation }) },
    integrity: { canonicalDigest: recordDigest, chainLink: null },
    nonRepudiation,
  });
  const form = { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm: false };

  it('reads the mandate form as one of the three forms of v1.0', () => {
    expect(signoffExpectationViolation(form)).toBeNull();
    expect(describeSignoffExpectationViolation('unknown_members')).toMatch(/mandateAssertion/);
    expect(signoffExpectationViolation({ ...form, confirm: 1 })).toBe('invalid_confirm');
    expect(signoffExpectationViolation({ ...form, mandateSeq: 0 })).toBe('invalid_mandate_seq');
    expect(signoffExpectationViolation({ ...form, totals: { paid: '3' } })).toBe('invalid_totals');
    expect(signoffExpectationViolation({ ...form, mandateAssertion: 'x' })).toBe('invalid_mandate_assertion');
    expect(signoffExpectationViolation({ ...form, extra: 1 })).toBe('unknown_members');
  });

  it.each([
    ['24: everything binds', form, () => ({ mandate: block() }), { valid: true }],
    ['18: no block', form, () => ({}), { valid: false, reason: 'mandate_stripped' }],
    ['17: a session sign-off', form, () => ({ mandate: block(), signoff: { statement: { mode: 'session' }, sessionSeq: 1 } }), { valid: false, reason: 'session_signoff_not_expected' }],
    ['19: a malformed statement', form, () => ({ mandate: { ...block(), statement: { ...statement(), mode: 'batch' } } }), { valid: false, reason: 'malformed_mandate_statement' }],
    ['19: a statement carrying signerName', form, () => ({ mandate: { ...block(), statement: { ...statement(), signerName: 'U2Ft' } } }), { valid: false, reason: 'malformed_mandate_statement' }],
    ['20: another assertion digest', { ...form, mandateAssertion: '00'.repeat(32) }, () => ({ mandate: block() }), { valid: false, reason: 'mandate_assertion_mismatch' }],
    ['22: another document', form, () => ({ mandate: { ...block(), document: { ...doc(), mandateId: '00000000-0000-0000-0000-000000000000' } } }), { valid: false, reason: 'mandate_document_mismatch' }],
    ['23: a confirmation owed and missing', { ...form, confirm: true }, () => ({ mandate: block() }), { valid: null, reason: 'confirmation_missing' }],
  ])('%s', (_name, expectation, nr, expected) => {
    expect(checkSignoffExpectation(envelope(expectation, nr()))).toEqual(expected);
  });

  it('20: an ES256 signature that is not DER', () => {
    const es = es256Assertion(W4_CHALLENGE);
    const exp = { ...form, mandateAssertion: assertionDigest(es)! };
    expect(checkSignoffExpectation(envelope(exp, { mandate: { ...block(), assertion: { ...es, signature: 'AAAA' } } }))).toEqual({
      valid: false, reason: 'mandate_assertion_mismatch',
    });
  });

  it('21: an assertion presenting another challenge', () => {
    const other = es256Assertion('another-challenge');
    const exp = { ...form, mandateAssertion: assertionDigest(other)! };
    expect(checkSignoffExpectation(envelope(exp, { mandate: { ...block(), assertion: other } }))).toEqual({
      valid: false, reason: 'mandate_unbound',
    });
  });

  it('23: a confirmation presenting the record’s confirmation challenge', () => {
    const recordDigest = 'cd'.repeat(32);
    const confirmation = es256Assertion(mandateConfirmationChallenge(recordDigest));
    expect(checkSignoffExpectation(envelope({ ...form, confirm: true }, { mandate: block(), confirmation }, recordDigest))).toEqual({ valid: true });
  });

  it('22: a statement whose signer is not the document’s principal', () => {
    const otherStatement = { ...statement(), signer: 'other-1' };
    const otherAssertion = es256Assertion(mandateStatementChallenge(mandateStatementDigest(otherStatement)!));
    const exp = { ...form, mandateAssertion: assertionDigest(otherAssertion)! };
    const nr = { mandate: { statement: otherStatement, assertion: otherAssertion, assertionTimestamp: null, document: doc() } };
    expect(checkSignoffExpectation(envelope(exp, nr))).toEqual({ valid: false, reason: 'mandate_document_mismatch' });
  });

  it('1a: a mandate block under a non-mandate expectation, on every record', () => {
    expect(checkSignoffExpectation(envelope(null as never, { mandate: block() }))).toEqual({ valid: false, reason: 'mandate_not_expected' });
    expect(
      checkSignoffExpectation({
        payload: { schemaVersion: 'v1.0', signoffExpectation: { policyDigest: 'c6'.repeat(32) } },
        integrity: { canonicalDigest: 'ab'.repeat(32) },
        nonRepudiation: { mandate: block() },
      }),
    ).toEqual({ valid: false, reason: 'mandate_not_expected' });
  });

  it('caps a mandate block at 48 KiB', () => {
    expect(mandateBlockViolation(block())).toBeNull();
    expect(mandateBlockViolation({ ...block(), assertionTimestamp: 'x'.repeat(49 * 1024) })?.code).toBe('mandate_block_too_large');
  });
});

/** W5, assembled from W4 by the issuance builder. */
function w5(): EvidenceEnvelope {
  return assembleEnvelope(
    mandateIssuanceInput({
      document: doc() as MandateDocument,
      statement: statement() as MandateStatement,
      assertion: W4_ASSERTION,
      reason: 'Claims-triage mandate for Q4 2026',
    }),
    {
      evidenceId: W5_EVIDENCE_ID,
      sequenceNumber: 1,
      capturedAt: '2026-09-30T14:05:30.000Z',
      systemRecord: 'mandate',
      attestation: { mandateIssuance: { statement: statement(), assertion: W4_ASSERTION, assertionTimestamp: null, document: doc() } },
    },
  );
}

describe('issuance records (W5; Verification §4.12 mandate.issuance)', () => {
  it('the issuance builder reproduces W5: 633 canonical bytes and its digest', () => {
    const env = w5();
    expect(env.integrity.canonicalDigest).toBe(W5_DIGEST);
    expect(env.payload.decider).toEqual({ kind: 'human', id: 'acct:user-2c9d', agent: null, credential: null, freshness: null });
    expect(checkMandateIssuance(env)).toEqual({ outcome: 'checked-correct', valid: true });
    expect(verifyEnvelope(env).mandate?.issuance).toEqual({ outcome: 'checked-correct', valid: true });
  });

  it('is refused without systemRecord: tzun:mandate is reserved', () => {
    expect(() =>
      assembleEnvelope(
        mandateIssuanceInput({ document: doc(), statement: statement(), assertion: W4_ASSERTION, reason: 'r' }),
        { capturedAt: '2026-09-30T14:05:30.000Z' },
      ),
    ).toThrow(expect.objectContaining({ code: 'reserved_ai_system_id' }));
  });

  it("is refused under systemRecord: 'link', which admits only link records", () => {
    expect(() =>
      assembleEnvelope(
        mandateIssuanceInput({ document: doc(), statement: statement(), assertion: W4_ASSERTION, reason: 'r' }),
        { capturedAt: '2026-09-30T14:05:30.000Z', systemRecord: 'link' },
      ),
    ).toThrow(expect.objectContaining({ code: 'reserved_ai_system_id' }));
  });

  const issuance = (
    over: { aiOutput?: Record<string, unknown>; block?: unknown; aiSystemId?: string; decider?: unknown } = {},
  ) => {
    const env = w5() as unknown as { payload: Record<string, unknown>; nonRepudiation: Record<string, unknown> };
    if (over.aiOutput) env.payload.aiOutput = over.aiOutput;
    if (over.aiSystemId) env.payload.aiSystemId = over.aiSystemId;
    if (over.decider !== undefined) env.payload.decider = over.decider;
    if (over.block === null) delete env.nonRepudiation.mandateIssuance;
    else if (over.block !== undefined) env.nonRepudiation.mandateIssuance = over.block;
    return env;
  };

  it('is not reported on an ordinary record', () => {
    expect(checkMandateIssuance({ payload: { aiSystemId: 'x', action: 'y' }, nonRepudiation: {} })).toBeNull();
  });

  it('reports each broken link', () => {
    expect(checkMandateIssuance(issuance({ block: null }))?.reason).toBe('issuance_material_stripped');
    expect(checkMandateIssuance(issuance({ aiSystemId: 'claims' }))?.reason).toBe('issuance_not_expected');
    const ai = issuance().payload.aiOutput as Record<string, unknown>;
    expect(checkMandateIssuance(issuance({ aiOutput: { ...ai, mandateDigest: '00'.repeat(32) } }))).toMatchObject({ link: 'document' });
    expect(checkMandateIssuance(issuance({ aiOutput: { ...ai, statementDigest: '00'.repeat(32) } }))).toMatchObject({ link: 'statement' });
    expect(checkMandateIssuance(issuance({ aiOutput: { ...ai, assertionDigest: '00'.repeat(32) } }))).toMatchObject({ link: 'assertion' });
    const other = es256Assertion('another');
    expect(
      checkMandateIssuance(issuance({ block: { statement: statement(), assertion: other, assertionTimestamp: null, document: doc() } })),
    ).toMatchObject({ link: 'challenge' });
    const principal = { kind: 'human', id: 'acct:user-2c9d', agent: null, credential: null, freshness: null };
    expect(checkMandateIssuance(issuance({ decider: { ...principal, id: 'acct:other-1' } }))).toMatchObject({ link: 'decider' });
    expect(checkMandateIssuance(issuance({ decider: null }))).toMatchObject({ link: 'decider' });
  });

  it('a successor issuance record supersedes its predecessor’s', () => {
    const input = mandateIssuanceInput({
      document: { ...doc(), mandateId: '6b1f0e2a-7c3d-4e5f-8a9b-0c1d2e3f4a5c', predecessor: W4_MANDATE_DIGEST },
      statement: statement(),
      assertion: W4_ASSERTION,
      reason: 'renewed',
      predecessorIssuance: W5_TARGET,
    });
    expect(input.links).toEqual([{ rel: 'supersedes', target: W5_TARGET, attrs: null }]);
  });
});

describe('the mandate lifecycle (Record §9.6)', () => {
  const base = () => {
    const p = mandatedPayload() as Record<string, unknown>;
    delete p.signoffExpectation;
    return p;
  };
  const open = { state: 'open' as const, used: 40, totals: { paid: 5110000 } };

  it("plans W6's claim: slot 41 and the running total, confirm false", () => {
    const plan = planMandateClaim({ document: doc(), mandate: open, payload: base(), assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET });
    expect(plan).toEqual({
      ok: true,
      expectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm: false },
      links: [{ rel: 'mandate', target: W5_TARGET, attrs: null }],
      expectUsed: 40,
      caps: [{ cap: 'paid', expectTotal: 5110000, newTotal: 5230000 }],
      confirmHolding: [],
    });
  });

  it('the planned W6 assembles to its digest, its mandate link held to its rules', () => {
    const plan = planMandateClaim({ document: doc(), mandate: open, payload: base(), assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET });
    if (!plan.ok) throw new Error(plan.code);
    const aiOutput = { amountMinor: 120000, fraudFlag: false, recommendation: 'approve' };
    const env = assembleEnvelope(
      {
        aiSystemId: 'claims-triage-v4',
        aiOutput,
        action: 'approve',
        reason: 'Policy active; invoice matches the repair estimate',
        decider: {
          kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT, credential: null,
          freshness: 'eip155:1@23652000:0x' + '5e'.repeat(32),
        },
        contributions: {
          pipeline: null,
          externals: [],
          steps: [{
            ...proposeStep(aiOutput),
            output: 'sha256:252a3512d90f1214170196efddbaba73a8c02f7a9dd1ba6cb42588ad64d44fe0',
          } as never],
        },
        links: [{ rel: 'mandate', target: W5_TARGET, attrs: null }],
      },
      {
        evidenceId: '7a2c0d4e-2222-4b2b-9b2b-000000000141',
        sequenceNumber: 141,
        capturedAt: '2026-11-20T10:14:50.000Z',
        signoffExpectation: plan.expectation,
        attestation: { mandate: { statement: statement(), assertion: W4_ASSERTION, assertionTimestamp: null, document: doc() } },
      },
    );
    expect(env.integrity.canonicalDigest).toBe('057a50035ba3eb6b0ae82b2cb8e1aa8e22bf8a223e5470c135cce67ab58766fe');
    const result = verifyEnvelope(env);
    expect(result.signoffExpectationValid).toBe(true);
    expect(result.mandate?.scope).toEqual({ outcome: 'checked-correct', valid: true });
    expect(result.mandate?.limits).toEqual({ outcome: 'checked-correct', valid: true, slot: 41, totals: { paid: 5230000 } });
    const held = w5();
    const links = checkLinks(env.payload, {
      resolver: { byDigest: (d) => (d === W5_DIGEST ? { payload: held.payload as never, digest: W5_DIGEST, origin: CLAIMS_ORIGIN } : null) },
    });
    expect(links.relations).toEqual([{ index: 0, rel: 'mandate', outcome: 'checked-correct', valid: true, targetHeld: true }]);
  });

  it.each([
    ['a decider that is not agent-mandated', { decider: { kind: 'agent', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null } }, open, 'agent_not_in_mandate'],
    ['a decider not among the agents', { decider: { kind: 'agent-mandated', id: 'spiffe://x.example/y', agent: 'sha256:' + '11'.repeat(32), credential: null, freshness: null } }, open, 'agent_not_in_mandate'],
    ['a revoked mandate', {}, { ...open, state: 'revoked' as const }, 'mandate_not_open'],
    ['a capture before the window', { capturedAt: '2026-09-30T00:00:00.000Z' }, open, 'outside_validity'],
    ['another schema version', { schemaVersion: 'v1.1' }, open, 'schema_version_mismatch'],
    ['a confirm predicate undeterminable', { aiOutput: { amountMinor: 1 } }, open, 'confirm_undeterminable'],
    ['an action outside scope', { action: 'deny' }, open, 'outside_scope'],
    ['a model outside scope', { contributions: { pipeline: null, externals: [], steps: [proposeStep({}, 'sha256:' + '99'.repeat(32))] } }, open, 'outside_scope'],
    ['no step model while the mandate names models', { contributions: null }, open, 'scope_undeterminable'],
    ['a cap value that is not an integer, read by a scope predicate too', { aiOutput: { amountMinor: '3', fraudFlag: false } }, open, 'scope_undeterminable'],
    ['a full mandate', {}, { ...open, used: 10000 }, 'mandate_full'],
    ['a total past its cap', {}, { ...open, totals: { paid: 249990000 } }, 'cap_exceeded'],
  ])('refuses %s', (_name, over, mandate, code) => {
    const plan = planMandateClaim({ document: doc(), mandate, payload: { ...base(), ...over }, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET });
    expect(plan).toMatchObject({ ok: false, code });
  });

  it('refuses a cap value that is not an integer', () => {
    const d = doc();
    d.limits.cumulative.paid.path = '/aiOutput/paidMinor';
    const plan = planMandateClaim({
      document: d, mandate: open, payload: { ...base(), aiOutput: { amountMinor: 1, fraudFlag: false, paidMinor: 1.5 } }, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET,
    });
    expect(plan).toMatchObject({ ok: false, code: 'cap_value_invalid', field: 'limits.cumulative.paid' });
  });

  it('reports the scope before an undeterminable confirmation', () => {
    const plan = planMandateClaim({
      document: doc(), mandate: open, payload: { ...base(), action: 'deny', aiOutput: { amountMinor: 1 } }, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET,
    });
    expect(plan).toMatchObject({ ok: false, code: 'outside_scope' });
  });

  it('a claim past the window says the mandate has expired', () => {
    const plan = planMandateClaim({ document: doc(), mandate: open, payload: { ...base(), capturedAt: '2027-01-01T00:00:00.000Z' }, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET });
    expect(plan).toMatchObject({ ok: false, code: 'outside_validity', expired: true });
    expect(mandateExpiredAt('2026-12-31T23:59:59.999Z', '2027-01-01T00:00:00.000Z')).toBe(true);
    expect(mandateExpiredAt('2026-12-31T23:59:59.999Z', '2026-12-31T23:59:59.999Z')).toBe(false);
    expect(mandateExpiredAt(null, '2099-01-01T00:00:00.000Z')).toBe(false);
  });

  it('adds the mandate link once, sorted, and reads the scope over the links the record stores', () => {
    const reviews = { rel: 'reviews', target: { digest: 'e'.repeat(64), evidenceId: null, locator: null }, attrs: null };
    const before = { ...base(), links: [reviews] };
    const plan = planMandateClaim({ document: doc(), mandate: open, payload: before, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET });
    if (!plan.ok) throw new Error(plan.code);
    expect(plan.links).toEqual([{ rel: 'mandate', target: W5_TARGET, attrs: null }, reviews]);
    const noLinks = planMandateClaim({ document: doc(), mandate: open, payload: { ...base(), links: null }, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET });
    expect(noLinks).toMatchObject({ ok: true, links: [{ rel: 'mandate', target: W5_TARGET, attrs: null }] });
    // A predicate over /links: the claim reads the list with the mandate link, as the verifier will.
    const d = doc();
    d.scope.predicates = { ...d.scope.predicates, firstIsReview: { path: '/links/0/rel', op: 'eq', value: 'reviews', quant: null } };
    const refused = planMandateClaim({ document: d, mandate: open, payload: before, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET });
    expect(refused).toMatchObject({ ok: false, code: 'outside_scope', findings: [{ constraint: 'predicate', name: 'firstIsReview' }] });
    d.scope.predicates.firstIsReview.value = 'mandate';
    const within = planMandateClaim({ document: d, mandate: open, payload: before, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET });
    if (!within.ok) throw new Error(within.code);
    expect(evaluateMandateScope(d, { ...before, links: within.links, signoffExpectation: within.expectation }).verdict).toBe('within');
  });

  it('never throws on links or an issuance target that do not meet the grammar, leaving them to the payload gate', () => {
    for (const [links, issuance] of [
      ['x', W5_TARGET],
      [[{ rel: 1 }], W5_TARGET],
      [null, undefined],
      [null, { digest: 'nothex', evidenceId: null, locator: null }],
    ] as const) {
      expect(() =>
        planMandateClaim({ document: doc(), mandate: open, payload: { ...base(), links }, assertionDigest: W4_ASSERTION_DIGEST, issuance: issuance as never }),
      ).not.toThrow();
    }
  });

  it('owes a confirmation when a confirm predicate holds', () => {
    const plan = planMandateClaim({
      document: doc(), mandate: open, payload: { ...base(), aiOutput: { amountMinor: 1000, fraudFlag: true } }, assertionDigest: W4_ASSERTION_DIGEST, issuance: W5_TARGET,
    });
    expect(plan).toMatchObject({ ok: true, expectation: { confirm: true }, confirmHolding: ['fraud'] });
  });

  it('a revocation names its instant, no later than its capture, and links the issuance record', () => {
    expect(revocationInstantViolation('2026-11-20T10:00:00.000Z', '2026-11-20T10:00:00.000Z')).toBeNull();
    expect(revocationInstantViolation('2026-11-19T10:00:00.000Z', '2026-11-20T10:00:00.000Z')).toBeNull();
    expect(revocationInstantViolation('2026-11-21T10:00:00.000Z', '2026-11-20T10:00:00.000Z')?.code).toBe('invalid_revocation_instant');
    expect(revocationInstantViolation('2026-11-20T10:00:00Z', '2026-11-20T10:00:00.000Z')?.code).toBe('invalid_revocation_instant');
    const input = mandateRevocationInput({
      mandateDigest: W4_MANDATE_DIGEST, statementDigest: W4_STATEMENT_DIGEST, claimedRevocationInstant: '2026-11-20T10:00:00.000Z',
      reason: 'Fraud pattern under review', revokerUserId: 'user-2c9d', issuance: W5_TARGET,
    });
    const env = assembleEnvelope(input, { capturedAt: '2026-11-20T10:00:00.000Z', systemRecord: 'mandate' });
    expect(env.payload.links).toEqual([{ rel: 'revokes', target: W5_TARGET, attrs: null }]);
    const held = w5();
    const r = checkLinks(env.payload, {
      resolver: { byDigest: (d) => (d === W5_DIGEST ? { payload: held.payload as never, digest: W5_DIGEST, origin: CLAIMS_ORIGIN } : null) },
    });
    expect(r.relations[0]).toMatchObject({ rel: 'revokes', outcome: 'checked-correct' });
    // Without its revokes link a revocation record is refused.
    expect(() => assembleEnvelope({ ...input, links: null }, { systemRecord: 'mandate' })).toThrow(
      expect.objectContaining({ code: 'required_link_missing' }),
    );
  });

  it('refuses a successor naming another principal, or another predecessor', () => {
    const successor = { ...doc(), predecessor: W4_MANDATE_DIGEST };
    expect(predecessorPrincipalViolation(successor, doc())).toBeNull();
    expect(predecessorPrincipalViolation({ ...successor, principal: { signer: 'other-1', credential: null } }, doc())?.code).toBe(
      'predecessor_principal_mismatch',
    );
    expect(predecessorPrincipalViolation({ ...successor, predecessor: '00'.repeat(32) }, doc())?.code).toBe('predecessor_principal_mismatch');
  });

  it('refuses a confirmation that is not owed, and a second one', () => {
    const owed = { payload: { signoffExpectation: { ...mandatedPayload().signoffExpectation, confirm: true } }, nonRepudiation: {} };
    expect(mandateConfirmationViolation(owed)).toBeNull();
    expect(mandateConfirmationViolation({ ...owed, nonRepudiation: { confirmation: W4_ASSERTION } })?.code).toBe('already_confirmed');
    expect(mandateConfirmationViolation({ payload: { signoffExpectation: mandatedPayload().signoffExpectation } })?.code).toBe('confirmation_not_owed');
    expect(mandateConfirmationViolation({ payload: { signoffExpectation: { policyDigest: 'c6'.repeat(32) } } })?.code).toBe('confirmation_not_owed');
  });
});

describe('a mandated record through verifyEnvelope', () => {
  const mandated = (aiOutput: Record<string, unknown>, confirm: boolean) =>
    assembleEnvelope(
      {
        aiSystemId: 'claims-triage-v4',
        aiOutput,
        action: 'approve',
        reason: 'within limits',
        decider: { kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null },
        contributions: { pipeline: null, externals: [], steps: [proposeStep(aiOutput) as never] },
        links: [{ rel: 'mandate', target: W5_TARGET, attrs: null }],
      },
      {
        evidenceId: '6b1f0e2a-7c3d-4e5f-8a9b-0c1d2e3f4a41',
        sequenceNumber: 1,
        capturedAt: '2026-10-02T10:00:00.000Z',
        signoffExpectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm },
        attestation: { mandate: { statement: statement(), assertion: W4_ASSERTION, assertionTimestamp: null, document: doc() } },
      },
    );

  it('checks scope and limits while the owed confirmation is missing', () => {
    const result = verifyEnvelope(mandated({ amountMinor: 120000, fraudFlag: true }, true));
    expect(result.verified).toBe(true);
    expect([result.signoffExpectationValid, result.signoffExpectationReason]).toEqual([null, 'confirmation_missing']);
    expect(result.mandate?.scope).toEqual({ outcome: 'checked-correct', valid: true });
    expect(result.mandate?.limits).toEqual({ outcome: 'checked-correct', valid: true, slot: 41, totals: { paid: 5230000 } });
  });

  it('reads scope_undeterminable for a record that drops the flagged field and owes no confirmation', () => {
    const result = verifyEnvelope(mandated({ amountMinor: 120000 }, false));
    expect(result.signoffExpectationValid).toBe(true);
    expect(result.mandate?.scope).toEqual({
      outcome: 'not-checked', valid: null, reason: 'scope_undeterminable', undeterminable: [{ constraint: 'confirm', name: 'fraud' }],
    });
  });

  it('refuses a mandate-form record without its mandate link, and reads one stripped of it as link_rule_violated', () => {
    const env = mandated({ amountMinor: 120000, fraudFlag: false }, false);
    const stripped = JSON.parse(JSON.stringify(env.payload));
    stripped.links = null;
    expect(checkLinks(stripped)).toMatchObject({ outcome: 'checked-wrong', reason: 'link_rule_violated', rule: 'mandate_link' });
  });
});
