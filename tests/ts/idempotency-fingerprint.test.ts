/**
 * The idempotency fingerprint, one engine function for both sides.
 *
 * The replay rule — same key and same caller input replays, same key and
 * different input is a conflict — is only as good as "same input". The
 * fingerprint covers what the CALLER chose and nothing the SDK fills in per
 * attempt, so a retry, which is a new envelope with a fresh evidenceId,
 * capturedAt and sequence number, fingerprints the same. The field set is
 * the 0.8.0 rule (`action`, `reason`, the decider's kind, id, agent and
 * credential, contributions and links); the vectors below are the engine's,
 * reproduced by an independent implementation (sorted-key JSON, SHA-256), and
 * are the ones the hosted service pins when it takes the rule.
 */
import { captureIdempotencyFingerprint } from '@tzun/engine';
import type { EvidenceEnvelope } from '@tzun/engine';

function sdkEnvelope(): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: '5f0c1f0e-1111-4a1a-9a1a-000000000001', schemaVersion: 'v1.0', aiSystemId: 'loan-model',
      aiOutput: { recommendation: 'approve', confidence: 0.94, notes: ['a', 'ü'] }, action: 'approved',
      reason: 'All criteria met', capturedAt: '2026-09-19T10:00:00.000Z', sequenceNumber: 7, contributions: null, signoffExpectation: null,
    },
    integrity: { canonicalDigest: 'd'.repeat(64), chainLink: 'c'.repeat(64) },
    nonRepudiation: { rfc3161Token: 'tok', webauthnAssertion: { id: 'cred-1', response: { signature: 'sig' } } } as never,
    custodyChain: [
      { timestamp: '2026-09-19T10:00:00.000Z', actor: 'acct:u-test', action: 'decision_captured', systemId: 'loan-model' },
    ],
    attestationStatus: 'partial',
  };
}

describe('captureIdempotencyFingerprint — the vectors', () => {
  const vectors: Array<[string, Parameters<typeof captureIdempotencyFingerprint>[0], string]> = [
    ['partial, an SDK-built envelope', { completeness: 'partial', envelope: sdkEnvelope() },
      'sha256:cc2439b76352ef9d90291dacc236d7a73b76a6490c72d507fca6fe016cda1c2d'],
    ['partial, a named chain', { completeness: 'partial', chainId: 'tenant-a', envelope: sdkEnvelope() },
      'sha256:88b7d1f7e7baa87767766dad63e62a6a253d6a44d3a24fcac23351f100c95a7d'],
    ['raw, with a capturedAt claim',
      { completeness: 'raw', payload: { aiOutput: { x: 1 }, action: 'approved' }, capturedAt: '2026-01-01T00:00:00.000Z' },
      'sha256:b312b84f227bd9a49e61f9155ddda6903df641a57e7d25eb943011610a8e85b3'],
    ['raw, no claim', { completeness: 'raw', payload: { b: 2, a: 1 } },
      'sha256:de12f7dd071eddaabbbe4e177f6433dd085c4432d30ab1f540c88c4274c534dd'],
  ];
  it.each(vectors)('%s', (_name, input, expected) => {
    expect(captureIdempotencyFingerprint(input)).toBe(expected);
  });
});

/**
 * A non-null signoff expectation is fingerprinted; a null one is left out,
 * so every vector above is unchanged. The hosted service computes its own
 * fingerprint and takes this rule in its 0.7 bump; these are the vectors it
 * pins when it does. Its `requestFingerprint` before that bump (copied
 * verbatim) gives the `sealed, no expectation` vector below, and for
 * each partial or sealed input with an expectation gives the vector of the
 * same input without one: a retry there under the same key replays. The raw
 * vector is the same on both sides, because a raw payload is fingerprinted
 * whole. An independent implementation of the rule (sorted-key JSON, SHA-256)
 * reproduces every vector in this file.
 */
describe('captureIdempotencyFingerprint — a non-null signoff expectation (vectors for the hosted service to pin)', () => {
  const withExpectation = (expectation: EvidenceEnvelope['payload']['signoffExpectation']): EvidenceEnvelope => {
    const envelope = sdkEnvelope();
    envelope.payload.signoffExpectation = expectation;
    return envelope;
  };
  const policy = { policyDigest: 'a'.repeat(64) };
  const session = { statementDigest: 'b'.repeat(64), sessionSeq: 3 };

  const vectors: Array<[string, Parameters<typeof captureIdempotencyFingerprint>[0], string]> = [
    ['sealed, no expectation', { completeness: 'sealed', envelope: sdkEnvelope() },
      'sha256:a86499eb0f329c5183d10baa8157ebd37e6932035e535e63f6db0088776c41fb'],
    ['partial, a policy expectation', { completeness: 'partial', envelope: withExpectation(policy) },
      'sha256:724e747801f923d12a4d41a35eff1e3388454535f4037186d595bba4265f2220'],
    ['partial, a session expectation', { completeness: 'partial', envelope: withExpectation(session) },
      'sha256:eba31dc6f88f1e399f3f3e13d548543b68852822f7eedea9f672cf79b50765a6'],
    ['sealed, a policy expectation', { completeness: 'sealed', envelope: withExpectation(policy) },
      'sha256:8b771d3ca257c840fb3e0d20eb26f3b80f4168c6f92f97c06451b81f8c7ca33b'],
    ['partial, a named chain and a session expectation', { completeness: 'partial', chainId: 'tenant-a', envelope: withExpectation(session) },
      'sha256:10c7a11da0605af048f72ff76598bfe37b7e2ec132caa6bc2a7ca1d3a2d4d285'],
    ['raw, a payload that carries an expectation',
      { completeness: 'raw', payload: { aiOutput: { x: 1 }, action: 'approved', signoffExpectation: policy } },
      'sha256:30ea68934261e95dbdb9017857d0e7f809368fd3f03c18d9dc92162980f2fd64'],
  ];
  it.each(vectors)('%s', (_name, input, expected) => {
    expect(captureIdempotencyFingerprint(input)).toBe(expected);
  });

  it('each expectation fingerprints apart from no expectation, and from each other', () => {
    const partial = (envelope: EvidenceEnvelope) => captureIdempotencyFingerprint({ completeness: 'partial', envelope });
    const prints = [partial(sdkEnvelope()), partial(withExpectation(policy)), partial(withExpectation(session))];
    expect(new Set(prints).size).toBe(3);
    const sealed = (envelope: EvidenceEnvelope) => captureIdempotencyFingerprint({ completeness: 'sealed', envelope });
    expect(sealed(withExpectation(policy))).not.toBe(sealed(sdkEnvelope()));
  });

  it('the order of an expectation’s members does not matter', () => {
    const reordered = withExpectation({ sessionSeq: 3, statementDigest: 'b'.repeat(64) } as typeof session);
    expect(captureIdempotencyFingerprint({ completeness: 'partial', envelope: reordered }))
      .toBe(captureIdempotencyFingerprint({ completeness: 'partial', envelope: withExpectation(session) }));
  });
});

describe('captureIdempotencyFingerprint — what a retry changes, and what it does not', () => {
  const base = () => captureIdempotencyFingerprint({ completeness: 'partial', envelope: sdkEnvelope() });

  const perAttempt: Array<[string, (e: EvidenceEnvelope) => void]> = [
    ['evidenceId', (e) => { e.payload.evidenceId = '5f0c1f0e-2222-4a1a-9a1a-000000000002'; }],
    ['capturedAt', (e) => { e.payload.capturedAt = '2026-09-19T10:00:07.123Z'; }],
    ['sequenceNumber', (e) => { e.payload.sequenceNumber = 8; }],
    ['schemaVersion', (e) => { (e.payload as { schemaVersion: string }).schemaVersion = 'v1.1'; }],
    ['canonicalDigest and chainLink', (e) => { e.integrity = { canonicalDigest: 'e'.repeat(64), chainLink: null }; }],
    ['decider freshness', (e) => { e.payload.decider = { ...e.payload.decider!, freshness: 'eip155:1@100:0x' + 'a'.repeat(64) }; }],
    ['attestationStatus', (e) => { e.attestationStatus = 'complete'; }],
    ['the SDK-obtained timestamp token', (e) => { (e.nonRepudiation as Record<string, unknown>).rfc3161Token = 'other'; }],
    ['a custody entry’s timestamp, entryHash and prevEntryHash', (e) => {
      Object.assign(e.custodyChain[0], { timestamp: '2026-09-19T10:00:07.123Z', entryHash: 'f'.repeat(64), prevEntryHash: null });
    }],
  ];
  it.each(perAttempt)('a retry with a new %s fingerprints the same', (_field, mutate) => {
    const envelope = sdkEnvelope();
    mutate(envelope);
    expect(captureIdempotencyFingerprint({ completeness: 'partial', envelope })).toBe(base());
  });

  const callerChose: Array<[string, (e: EvidenceEnvelope) => void]> = [
    ['reason', (e) => { e.payload.reason = 'Changed my mind'; }],
    ['action', (e) => { e.payload.action = 'rejected'; }],
    ['decider', (e) => { e.payload.decider = { kind: 'human', id: 'acct:u-other', agent: null, credential: null, freshness: null }; }],
    ['aiOutput', (e) => { (e.payload.aiOutput as Record<string, unknown>).confidence = 0.5; }],
    ['aiSystemId', (e) => { e.payload.aiSystemId = 'other-model'; }],
    ['the decision_captured actor', (e) => { e.custodyChain[0].actor = 'acct:u-bob'; }],
    ['the WebAuthn assertion', (e) => { (e.nonRepudiation as Record<string, unknown>).webauthnAssertion = { id: 'cred-2' }; }],
    // Hashed into the record: a replay would hand back a record owing another signature, or none.
    ['the signoff expectation', (e) => { e.payload.signoffExpectation = { policyDigest: 'a'.repeat(64) }; }],
  ];
  it.each(callerChose)('different %s is different input', (_field, mutate) => {
    const envelope = sdkEnvelope();
    mutate(envelope);
    expect(captureIdempotencyFingerprint({ completeness: 'partial', envelope })).not.toBe(base());
  });

  it('a null signoff expectation is fingerprinted as before the field existed; an absent one is null', () => {
    const absent = sdkEnvelope();
    delete (absent.payload as Partial<EvidenceEnvelope['payload']>).signoffExpectation;
    expect(captureIdempotencyFingerprint({ completeness: 'partial', envelope: absent })).toBe(base());
  });

  it('two different signoff expectations are different input', () => {
    const a = sdkEnvelope();
    a.payload.signoffExpectation = { policyDigest: 'a'.repeat(64) };
    const b = sdkEnvelope();
    b.payload.signoffExpectation = { policyDigest: 'b'.repeat(64) };
    expect(captureIdempotencyFingerprint({ completeness: 'partial', envelope: a }))
      .not.toBe(captureIdempotencyFingerprint({ completeness: 'partial', envelope: b }));
  });

  it('a different chain is different input; an absent chain is the default chain', () => {
    expect(captureIdempotencyFingerprint({ completeness: 'partial', chainId: 'other', envelope: sdkEnvelope() })).not.toBe(base());
    expect(captureIdempotencyFingerprint({ completeness: 'partial', chainId: 'default', envelope: sdkEnvelope() })).toBe(base());
  });

  it('the order of keys in the caller’s JSON does not matter', () => {
    const envelope = sdkEnvelope();
    envelope.payload.aiOutput = { notes: ['a', 'ü'], confidence: 0.94, recommendation: 'approve' };
    expect(captureIdempotencyFingerprint({ completeness: 'partial', envelope })).toBe(base());
  });
});
