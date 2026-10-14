import { buildContributions, checkContributions } from './contributions';
import {
  checkDecider,
  readerActorInconsistent,
  deciderAgreesWithExpectation,
  deciderCommitment,
  deciderMaterialViolation,
  deciderViolation,
  isKnownSchemeIdentifier,
  parseFreshnessReference,
  verifyDeciderOpening,
} from './decider';
import { webauthnChallengeForDigest } from './webauthn-binding';

const A = 'sha256:' + 'a1'.repeat(32);
const HASH = '0x' + '8a'.repeat(32);
const human = { kind: 'human', id: 'acct:u-4821', agent: null, credential: null, freshness: null };
const agent = { kind: 'agent', id: `desc:${A}`, agent: A, credential: null, freshness: null };

function clientData(challenge: string): string {
  return Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://rp.example' })).toString('base64url');
}

describe('deciderViolation (writer)', () => {
  it.each([
    ['human acct', human],
    ['agent desc', agent],
    ['agent-mandated spiffe', { ...agent, kind: 'agent-mandated', id: 'spiffe://claims.example/agent/triage' }],
    ['policy-engine jkt', { ...agent, kind: 'policy-engine', id: 'jkt:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k' }],
    ['human cmt', { ...human, id: 'cmt:' + 'ab'.repeat(32) }],
    ['credential and freshness', { ...human, credential: 'e0'.repeat(32), freshness: `eip155:1@9123456:${HASH}` }],
  ])('accepts %s', (_name, value) => {
    expect(deciderViolation(value)).toBeNull();
  });

  it.each([
    ['null (a decider is required)', null, 'not_an_object', 'decider'],
    ['an array', [], 'not_an_object', 'decider'],
    ['an extra member', { ...human, extra: 1 }, 'unknown_members', 'decider'],
    ['a missing member', { kind: 'human', id: 'acct:u', agent: null, credential: null }, 'missing_members', 'decider'],
    ['an unknown kind', { ...human, kind: 'committee' }, 'invalid_kind', 'decider.kind'],
    ['an email address', { ...human, id: 'acct:jane@example.com' }, 'invalid_identifier', 'decider.id'],
    ['an unknown scheme', { ...human, id: 'did:example:123' }, 'invalid_identifier', 'decider.id'],
    ['an identifier with a space', { ...human, id: 'acct:u 1' }, 'invalid_identifier', 'decider.id'],
    ['a malformed jkt', { ...agent, id: 'jkt:short' }, 'invalid_identifier', 'decider.id'],
    ['a spiffe id with no path', { ...agent, id: 'spiffe://claims.example' }, 'invalid_identifier', 'decider.id'],
    ['a spiffe dot segment', { ...agent, id: 'spiffe://claims.example/a/../b' }, 'invalid_identifier', 'decider.id'],
    ['an uppercase agent digest', { ...agent, agent: A.toUpperCase(), id: 'spiffe://x.example/a' }, 'invalid_agent_reference', 'decider.agent'],
    ['a prefixed credential', { ...human, credential: 'sha256:' + 'e0'.repeat(32) }, 'invalid_credential_reference', 'decider.credential'],
    ['a freshness with a leading-zero eip155 chain', { ...human, freshness: `eip155:01@1:${HASH}` }, 'invalid_freshness_reference', 'decider.freshness'],
    ['a freshness with a trailing newline', { ...human, freshness: `eip155:1@1:${HASH}\n` }, 'invalid_freshness_reference', 'decider.freshness'],
    ['a freshness with a non-ASCII digit', { ...human, freshness: `eip155:1@١:${HASH}` }, 'invalid_freshness_reference', 'decider.freshness'],
    ['a freshness block past 2^53 - 1', { ...human, freshness: `eip155:1@9007199254740992:${HASH}` }, 'invalid_freshness_reference', 'decider.freshness'],
    ['a human with an agent reference', { ...human, agent: A }, 'agent_reference_forbidden', 'decider.agent'],
    ['an agent with none', { ...agent, agent: null }, 'agent_reference_required', 'decider.agent'],
    ['a human under desc', { ...human, id: `desc:${A}` }, 'scheme_not_permitted', 'decider.id'],
    ['an agent under acct', { ...agent, id: 'acct:u-1' }, 'scheme_not_permitted', 'decider.id'],
    ['a desc naming another agent', { ...agent, id: 'desc:sha256:' + 'b2'.repeat(32) }, 'desc_identifier_mismatch', 'decider.id'],
  ])('refuses %s', (_name, value, code, field) => {
    const v = deciderViolation(value);
    expect(v?.code).toBe(code);
    expect(v?.field).toBe(field);
    expect(v?.message).not.toContain('jane@example.com');
  });
});

describe('identifiers and freshness references', () => {
  it('reads a finalized-block reference and its eip155 rule', () => {
    expect(parseFreshnessReference(`eip155:560048@123:${HASH}`)).toEqual({
      chain: 'eip155:560048', namespace: 'eip155', reference: '560048', blockNumber: 123, blockHash: HASH,
    });
    expect(parseFreshnessReference(`eip155:0@1:${HASH}`)).toBeNull();
    expect(parseFreshnessReference(`cosmos:cosmoshub-4@01:${HASH}`)).toBeNull();
    expect(parseFreshnessReference(`cosmos:cosmoshub-4@0:${HASH}`)).not.toBeNull();
  });

  it('applies each scheme value grammar', () => {
    expect(isKnownSchemeIdentifier('acct:' + 'a'.repeat(128))).toBe(true);
    expect(isKnownSchemeIdentifier('acct:' + 'a'.repeat(129))).toBe(false);
    expect(isKnownSchemeIdentifier('cmt:' + 'AB'.repeat(32))).toBe(false);
  });
});

describe('agreement with the signature expectation (12 cells)', () => {
  const policy = { policyDigest: 'c6'.repeat(32) };
  const session = { statementDigest: 'd7'.repeat(32), sessionSeq: 1 };
  const mandate = { mandateAssertion: 'e8'.repeat(32), mandateSeq: 1, totals: null, confirm: false };
  it.each([
    ['human', null, true], ['human', policy, true], ['human', session, true], ['human', mandate, false],
    ['agent', null, true], ['agent', policy, true], ['agent', session, false], ['agent', mandate, false],
    ['policy-engine', null, true], ['policy-engine', session, false], ['policy-engine', mandate, false],
    ['agent-mandated', null, false], ['agent-mandated', policy, false], ['agent-mandated', session, false],
    ['agent-mandated', mandate, true],
  ])('%s under %j → %s', (kind, expectation, agrees) => {
    expect(deciderAgreesWithExpectation(kind, expectation)).toBe(agrees);
  });

  it('does not decide an unknown kind or a malformed expectation', () => {
    expect(deciderAgreesWithExpectation('committee', null)).toBeNull();
    expect(deciderAgreesWithExpectation('agent-mandated', { ...mandate, confirm: 1 })).toBeNull();
  });
});

describe('material presented with a capture', () => {
  const digest = '2c6f289c0132a3369ec0f43339a077a7f4a0411d5ce536b0ed09250ff1c6661a';
  const assertion = {
    signature: 'AA', credentialKeyId: 'cred', algorithm: 'ES256',
    clientDataJSON: clientData(webauthnChallengeForDigest(digest)),
  };

  it('refuses an agent kind with a human assertion over this record', () => {
    expect(deciderMaterialViolation(agent, { digest, assertion })?.code).toBe('kind_contradicts_material');
    expect(deciderMaterialViolation({ ...agent, kind: 'policy-engine' }, { digest, assertion })?.code).toBe('kind_contradicts_material');
    expect(deciderMaterialViolation(human, { digest, assertion })).toBeNull();
  });

  it('accepts an agent kind whose assertion presents another challenge', () => {
    const other = { ...assertion, clientDataJSON: clientData('another-challenge') };
    expect(deciderMaterialViolation(agent, { digest, assertion: other })).toBeNull();
  });

  it('refuses an acct decider that differs from the credential user', () => {
    expect(deciderMaterialViolation(human, { assertionUserId: 'u-9999' })?.code).toBe('identity_contradicts_assertion');
    expect(deciderMaterialViolation(human, { assertionUserId: 'u-4821' })).toBeNull();
  });
});

describe('commitments', () => {
  const salt = Buffer.from(Array.from({ length: 32 }, (_, i) => i));

  it('reproduces the example commitment (Record §6.3)', () => {
    expect(deciderCommitment('acct:u-4821', salt)).toBe(
      'cmt:68912cfb4b69d6b38fa0b954aa41794a8e1359afc929ee1147a4fc94ef4c14d9',
    );
    expect(deciderCommitment('acct:u-4821', 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8')).toBe(
      'cmt:68912cfb4b69d6b38fa0b954aa41794a8e1359afc929ee1147a4fc94ef4c14d9',
    );
  });

  it('opens a commitment with its opening, and only with it', () => {
    const id = deciderCommitment('acct:u-4821', salt);
    expect(verifyDeciderOpening(id, { salt: salt.toString('base64url'), id: 'acct:u-4821' })).toBe(true);
    expect(verifyDeciderOpening(id, { salt: salt.toString('base64url'), id: 'acct:u-4822' })).toBe(false);
    expect(verifyDeciderOpening(id, { salt: 'not base64url!', id: 'acct:u-4821' })).toBe(false);
  });

  it('refuses a short salt and a commitment to a commitment', () => {
    expect(() => deciderCommitment('acct:u', Buffer.alloc(31))).toThrow(/32 bytes/);
    expect(() => deciderCommitment(`cmt:${'ab'.repeat(32)}`, salt)).toThrow(/another scheme/);
  });
});

describe('checkDecider (reader row)', () => {
  const record = (decider: unknown, extra: Record<string, unknown> = {}) => ({
    payload: { schemaVersion: 'v1.0', decider, signoffExpectation: null, ...extra },
    integrity: { canonicalDigest: '2c'.repeat(32), chainLink: null },
    nonRepudiation: {},
  });

  it('reads absent for null, and for a payload without the member', () => {
    expect(checkDecider(record(null))).toEqual({ outcome: 'not-checked', valid: null, reason: 'absent' });
    expect(checkDecider({ payload: { schemaVersion: 'v1.0' } }).reason).toBe('absent');
  });

  it('is checked-correct with the asserted level and the committed fact', () => {
    expect(checkDecider(record(human))).toEqual({
      outcome: 'checked-correct', valid: true, kind: 'human', scheme: 'acct', level: 'human-asserted',
    });
    expect(checkDecider(record({ ...human, id: 'cmt:' + 'ab'.repeat(32) }))).toMatchObject({ committed: true });
    expect(checkDecider(record(agent))).toMatchObject({ level: 'agent-asserted' });
  });

  it.each([
    ['a missing member', { kind: 'human', id: 'acct:u' }, 'checked-wrong', 'malformed_decider'],
    ['an unknown kind', { ...human, kind: 'committee' }, 'abstain', 'unsupported_decider_kind'],
    ['an inconsistent agent reference', { ...human, agent: A }, 'checked-wrong', 'decider_inconsistent'],
    ['a desc identifier naming another agent', { ...agent, id: 'desc:sha256:' + 'b2'.repeat(32) }, 'checked-wrong', 'decider_inconsistent'],
    ['a scheme the kind does not permit', { ...human, id: `desc:${A}` }, 'checked-wrong', 'decider_inconsistent'],
    ['an unknown scheme', { ...human, id: 'did:example:1' }, 'abstain', 'unsupported_identifier_scheme'],
  ])('%s → %s %s', (_n, decider, outcome, reason) => {
    expect(checkDecider(record(decider))).toMatchObject({ outcome, reason });
  });

  it('reports a kind the expectation contradicts', () => {
    const mandate = { mandateAssertion: 'e8'.repeat(32), mandateSeq: 1, totals: null, confirm: false };
    expect(checkDecider(record(human, { signoffExpectation: mandate }))).toMatchObject({
      outcome: 'checked-wrong', reason: 'decider_kind_contradicted',
    });
  });

  it('is blocked by a malformed expectation', () => {
    expect(checkDecider(record(human, { signoffExpectation: { nope: 1 } }))).toMatchObject({
      reason: 'blocked_by:signoff.expectation',
    });
  });

  it('reads material_unverified for an agent record a human signed, and human-proven undetermined for a human one', () => {
    const digest = '2c'.repeat(32);
    const signed = (decider: unknown) => ({
      ...record(decider),
      nonRepudiation: {
        webauthnAssertion: {
          signature: 'AA', credentialKeyId: 'c', algorithm: 'ES256',
          clientDataJSON: clientData(webauthnChallengeForDigest(digest)),
        },
      },
    });
    expect(checkDecider(signed(agent))).toEqual({
      outcome: 'not-checked', valid: null, reason: 'material_unverified', kind: 'agent', scheme: 'desc',
      kindContradiction: 'undetermined',
    });
    expect(checkDecider(signed(human))).toMatchObject({ outcome: 'checked-correct', levelUndetermined: 'human-proven' });
  });
});

describe('one identifier, one verdict, in the decider and contributions rows', () => {
  // The per-scheme value grammars (acct, spiffe, jkt, cmt) are writer rules
  // (Record §6.3): a reader judges an identifier by the general grammar and the
  // consistency test alone, in both rows.
  it.each([
    ['an acct value a writer refuses (an email address)', 'acct:jane@acme.example'],
    ['a cmt value of the wrong length', 'cmt:abc'],
  ])('%s', (_name, id) => {
    const decider = { ...human, id };
    const record = {
      payload: { schemaVersion: 'v1.0', decider, signoffExpectation: null },
      integrity: { canonicalDigest: '2c'.repeat(32), chainLink: null },
      nonRepudiation: {},
    };
    expect(deciderViolation(decider)?.code).toBe('invalid_identifier');
    expect(checkDecider(record)).toMatchObject({ outcome: 'checked-correct' });
    const action = 'approve';
    const reason = 'r';
    const contributions = buildContributions(
      { steps: [{ role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null } }] },
      { decider: human, action, reason },
    );
    contributions.steps[0].actor!.id = id;
    const payload = { schemaVersion: 'v1.0', aiOutput: {}, action, reason, decider, contributions, links: null };
    expect(checkContributions(payload)).toMatchObject({ outcome: 'checked-correct' });
  });

  it('applies the same consistency test to a decider and a step actor', () => {
    expect(readerActorInconsistent('human', 'acct:jane@acme.example', null)).toBe(false);
    expect(readerActorInconsistent('human', 'acct:u-1', A)).toBe(true);
    expect(readerActorInconsistent('agent', `desc:${A}`, null)).toBe(true);
    expect(readerActorInconsistent('agent', 'desc:sha256:' + 'b2'.repeat(32), A)).toBe(true);
    expect(readerActorInconsistent('agent', 'acct:u-1', A)).toBe(true);
    expect(readerActorInconsistent('agent', 'did:example:1', A)).toBe(false);
  });
});
