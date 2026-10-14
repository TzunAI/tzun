/**
 * `payload.signoffExpectation` (Record §9.1): its place in the v1.0
 * hashed field set, its shape rule, the check a verifier makes with it, and
 * how a record captured before it existed is recognised. The cross-language
 * half of the same answers is vectors/signoff-expectation-vectors.json.
 */
import { createHash } from 'crypto';
import { canonicalSerialize } from './canonical';
import { computeDigest } from './digest';
import { assembleEnvelope } from './envelope';
import { StoreSchemaOutdatedError } from './errors';
import { buildMerkleTree, getMerkleProof, getMerkleRoot } from './merkle';
import { SchemaRegistry } from './schema-registry';
import {
  checkSignoffExpectation,
  signoffExpectationViolation,
  signoffStatementChallenge,
  signoffStatementDigest,
} from './signoff-expectation';
import {
  FIELD_SET_0_7,
  FIELD_SET_BEFORE_0_7,
  earlierFieldSet,
  recordFieldSetGeneration,
  recordPredatesSignoffExpectation,
} from './store-schema';
import { verifyEnvelope } from './verify';
import { webauthnChallengeForDigest } from './webauthn-binding';
import type { EvidenceEnvelope } from './types/evidence';

const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);
const V1_0 = new SchemaRegistry().get('v1.0')!.hashedFieldSet;

const input = {
  aiOutput: { r: 'approve' },
  action: 'approved',
  reason: 'ok',
  aiSystemId: 'sys',
  decider: { kind: 'human' as const, id: 'acct:u-1', agent: null, credential: null, freshness: null },
};

const sessionStatement = {
  v: 'tzun-signoff/1', mode: 'session', sessionId: '6f1c1f0e-8d6a-4f0e-9d6b-1a2b3c4d5e6f', signer: 'u1',
  signerName: 'SmFuZQ', meaning: 'approval', policyDigest: HEX_A, notBefore: 'none',
  openedAt: '2026-09-26T10:00:00.000Z', maxAgeMs: 1800000, maxRecords: 50,
};
const batchStatement = {
  v: 'tzun-signoff/1', mode: 'batch', batchId: '0e1c1f0e-8d6a-4f0e-9d6b-1a2b3c4d5e6f', signer: 'u1',
  signerName: 'SmFuZQ', meaning: 'approval', policyDigest: HEX_A, notBefore: 'none',
  merkleSpec: 'rfc6962', root: HEX_B, treeSize: 2,
};

function assertionFor(challenge: string) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge })).toString('base64url');
  return { signature: 'c2ln', credentialKeyId: 'cred', algorithm: 'ES256' as const, clientDataJSON };
}

/**
 * A batch sign-off covering the record whose digest is `digest`: the batch
 * tree over `[digest, HEX_B]`, the statement naming its root and size, the
 * record at leaf 0, and an assertion that presented the statement's challenge.
 */
function batchSignedBy(digest: string, edit: (statement: Record<string, unknown>) => void = () => {}) {
  const tree = buildMerkleTree([digest, HEX_B]);
  const statement: Record<string, unknown> = { ...batchStatement, root: getMerkleRoot(tree), treeSize: 2 };
  edit(statement);
  return {
    webauthnAssertion: assertionFor(signoffStatementChallenge(signoffStatementDigest(statement)!)),
    signoff: { statement, inclusion: { leafIndex: 0, path: getMerkleProof(tree, 0) } },
  };
}

function envelopeWith(expectation: unknown, nonRepudiation: Record<string, unknown> = {}): EvidenceEnvelope {
  const env = assembleEnvelope(input, { capturedAt: '2026-09-26T10:00:01.000Z' });
  env.payload.signoffExpectation = expectation as EvidenceEnvelope['payload']['signoffExpectation'];
  env.integrity.canonicalDigest = computeDigest(
    canonicalSerialize(env.payload as unknown as Record<string, unknown>, V1_0),
  );
  env.nonRepudiation = nonRepudiation as EvidenceEnvelope['nonRepudiation'];
  return env;
}

describe('the v1.0 hashed field set', () => {
  it('holds signoffExpectation among its eleven names', () => {
    expect(V1_0).toEqual([
      'action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider', 'evidenceId', 'links', 'reason',
      'sequenceNumber', 'signoffExpectation',
    ]);
  });

  it('writes the key as null when the payload has none', () => {
    expect(canonicalSerialize({ aiOutput: {} }, V1_0)).toContain('"signoffExpectation":null');
  });
});

describe('signoffExpectationViolation', () => {
  it.each([
    ['null', null],
    ['absent', undefined],
    ['the policy form', { policyDigest: HEX_A }],
    ['the session form', { statementDigest: HEX_A, sessionSeq: 1 }],
    ['the session form at the largest safe slot', { statementDigest: HEX_A, sessionSeq: Number.MAX_SAFE_INTEGER }],
  ])('accepts %s', (_name, value) => {
    expect(signoffExpectationViolation(value)).toBeNull();
  });

  it.each([
    ['a string', 'required', 'not_an_object'],
    ['an array', [HEX_A], 'not_an_object'],
    ['true', true, 'not_an_object'],
    ['an empty object', {}, 'unknown_members'],
    ['an unknown member beside policyDigest', { policyDigest: HEX_A, note: 'x' }, 'unknown_members'],
    ['both forms at once', { policyDigest: HEX_A, statementDigest: HEX_A, sessionSeq: 1 }, 'unknown_members'],
    ['statementDigest alone', { statementDigest: HEX_A }, 'unknown_members'],
    ['sessionSeq alone', { sessionSeq: 1 }, 'unknown_members'],
    ['an uppercase policy digest', { policyDigest: HEX_A.toUpperCase() }, 'invalid_policy_digest'],
    ['a 0x-prefixed policy digest', { policyDigest: '0x' + HEX_A.slice(2) }, 'invalid_policy_digest'],
    ['a short policy digest', { policyDigest: HEX_A.slice(1) }, 'invalid_policy_digest'],
    ['a policy digest with a trailing newline', { policyDigest: HEX_A + '\n' }, 'invalid_policy_digest'],
    ['a null policy digest', { policyDigest: null }, 'invalid_policy_digest'],
    ['a sha256:-prefixed statement digest', { statementDigest: 'sha256:' + HEX_A, sessionSeq: 1 }, 'invalid_statement_digest'],
    ['slot 0', { statementDigest: HEX_A, sessionSeq: 0 }, 'invalid_session_seq'],
    ['a negative slot', { statementDigest: HEX_A, sessionSeq: -1 }, 'invalid_session_seq'],
    ['a fractional slot', { statementDigest: HEX_A, sessionSeq: 1.5 }, 'invalid_session_seq'],
    ['a string slot', { statementDigest: HEX_A, sessionSeq: '1' }, 'invalid_session_seq'],
    ['a slot past 2^53 - 1', { statementDigest: HEX_A, sessionSeq: 2 ** 53 }, 'invalid_session_seq'],
  ])('refuses %s', (_name, value, violation) => {
    expect(signoffExpectationViolation(value)).toBe(violation);
  });
});

describe('signoffStatementDigest', () => {
  it('is SHA-256 of the statement canonical bytes', () => {
    const expected = createHash('sha256')
      .update(canonicalSerialize(sessionStatement, Object.keys(sessionStatement)))
      .digest('hex');
    expect(signoffStatementDigest(sessionStatement)).toBe(expected);
    expect(signoffStatementDigest({ ...sessionStatement })).toBe(expected);
  });

  it('is null for a value that is not a plain object', () => {
    expect(signoffStatementDigest(null)).toBeNull();
    expect(signoffStatementDigest('statement')).toBeNull();
    expect(signoffStatementDigest([sessionStatement])).toBeNull();
  });

  it('takes the largest safe integer', () => {
    expect(signoffStatementDigest({ ...sessionStatement, maxRecords: Number.MAX_SAFE_INTEGER })).toMatch(/^[0-9a-f]{64}$/);
  });

  // Record §9.4 defines canonical bytes only for printable-ASCII strings and
  // non-negative safe integers. A number past 2^53 - 1 in particular is read
  // differently by JavaScript's JSON.parse (rounded) and Python's (exact), so
  // hashing it would give the two SDKs different digests.
  it.each([
    ['an integer past 2^53 - 1', { maxRecords: 2 ** 53 }],
    ['a negative integer', { maxRecords: -1 }],
    ['a fraction', { maxAgeMs: 1.5 }],
    ['a boolean', { maxRecords: true }],
    ['null', { notBefore: null }],
    ['a nested object', { signer: { id: 'u1' } }],
    ['an array', { signer: ['u1'] }],
    ['a non-ASCII string', { signer: 'Jos\u00e9' }],
    ['a control character', { signer: 'u1\n' }],
    ['a non-ASCII key', { 'sign\u00e9r': 'u1' }],
  ])('is null for a statement holding %s', (_name, change) => {
    expect(signoffStatementDigest({ ...sessionStatement, ...change })).toBeNull();
  });
});

describe('signoffStatementChallenge', () => {
  it('is base64url_nopad(SHA-256("tzun-signoff-v1" || statementDigest)) (Record §9.4)', () => {
    const digest = signoffStatementDigest(sessionStatement)!;
    const expected = createHash('sha256').update('tzun-signoff-v1' + digest).digest('base64url');
    expect(signoffStatementChallenge(digest)).toBe(expected);
    expect(expected).not.toContain('=');
  });

  it('never equals the per-record challenge of the same hex', () => {
    const digest = signoffStatementDigest(sessionStatement)!;
    expect(signoffStatementChallenge(digest)).not.toBe(webauthnChallengeForDigest(digest));
  });
});

describe('assembleEnvelope', () => {
  it('writes signoffExpectation: null by default, inside the digest', () => {
    const env = assembleEnvelope(input);
    expect(env.payload.signoffExpectation).toBeNull();
    expect(Object.prototype.hasOwnProperty.call(env.payload, 'signoffExpectation')).toBe(true);
    expect(verifyEnvelope(env).verified).toBe(true);
  });

  it('hashes the expectation: the same decision under another expectation has another digest', () => {
    const opts = { capturedAt: '2026-09-26T10:00:00.000Z', evidenceId: '6f1c1f0e-8d6a-4f0e-9d6b-1a2b3c4d5e6f' };
    const none = assembleEnvelope(input, { ...opts, signoffExpectation: null });
    const policy = assembleEnvelope(input, { ...opts, signoffExpectation: { policyDigest: HEX_A } });
    const session = assembleEnvelope(input, { ...opts, signoffExpectation: { statementDigest: HEX_A, sessionSeq: 1 } });
    const digests = new Set([none, policy, session].map((e) => e.integrity.canonicalDigest));
    expect(digests.size).toBe(3);
    expect(policy.payload.signoffExpectation).toEqual({ policyDigest: HEX_A });
  });

  it('refuses a value of neither form before building a digest', () => {
    expect(() =>
      assembleEnvelope(input, { signoffExpectation: { policyDigest: 'nope' } as never }),
    ).toThrow(/signoffExpectation\.policyDigest must be 64 lowercase hex/);
  });

  it('rewriting the expectation (to hide what the record owes) breaks the digest, and the rewritten value is not read', () => {
    const env = assembleEnvelope(input, { signoffExpectation: { policyDigest: HEX_A } });
    env.payload.signoffExpectation = null;
    const result = verifyEnvelope(env);
    expect(result.verified).toBe(false);
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('digest_invalid');
  });
});

describe('checkSignoffExpectation', () => {
  const sessionDigest = signoffStatementDigest(sessionStatement)!;

  it('null expectation, nothing carried: true', () => {
    expect(checkSignoffExpectation(envelopeWith(null))).toEqual({ valid: true });
  });

  it('absent key reads as null', () => {
    const env = envelopeWith(null);
    delete (env.payload as Partial<EvidenceEnvelope['payload']>).signoffExpectation;
    expect(checkSignoffExpectation(env)).toEqual({ valid: true });
  });

  it('null expectation, a per-record signature or a batch sign-off nobody required: true', () => {
    const env = envelopeWith(null);
    env.nonRepudiation = { webauthnAssertion: assertionFor(webauthnChallengeForDigest(env.integrity.canonicalDigest)) };
    expect(checkSignoffExpectation(env)).toEqual({ valid: true });
    const batch = envelopeWith(null);
    batch.nonRepudiation = batchSignedBy(batch.integrity.canonicalDigest) as EvidenceEnvelope['nonRepudiation'];
    expect(checkSignoffExpectation(batch)).toEqual({ valid: true });
  });

  it('null expectation, a session sign-off transplanted onto it: false', () => {
    const env = envelopeWith(null, {
      webauthnAssertion: assertionFor('x'),
      signoff: { statement: sessionStatement, sessionSeq: 3 },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'session_signoff_not_expected' });
  });

  // Nothing is owed, but a carried sign-off must bind. The reviewer's probe:
  // a session statement relabelled to mode batch with sessionSeq dropped read
  // true on a null record.
  describe('null expectation, a carried sign-off that does not bind: false, signoff_unbound', () => {
    const cases: Array<[string, (digest: string) => Record<string, unknown>]> = [
      ['a session sign-off relabelled as a batch one', () => ({
        webauthnAssertion: assertionFor(signoffStatementChallenge(sessionDigest)),
        signoff: { statement: { ...sessionStatement, mode: 'batch' } },
      })],
      ['a batch sign-off from a batch that does not hold the record', () => batchSignedBy(HEX_A)],
      ['an empty signoff block beside an unbound assertion', () => ({ webauthnAssertion: assertionFor('AAAA'), signoff: {} })],
      ['a signoff that is not an object beside the per-record assertion', (d) => ({
        webauthnAssertion: assertionFor(webauthnChallengeForDigest(d)),
        signoff: 'batch',
      })],
    ];
    it.each(cases)('%s', (_name, carried) => {
      const env = envelopeWith(null);
      env.nonRepudiation = carried(env.integrity.canonicalDigest) as EvidenceEnvelope['nonRepudiation'];
      expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'signoff_unbound' });
    });
  });

  it('null expectation, a batch block without an assertion carries no sign-off: true', () => {
    const env = envelopeWith(null);
    env.nonRepudiation = { signoff: batchSignedBy(env.integrity.canonicalDigest).signoff } as EvidenceEnvelope['nonRepudiation'];
    expect(checkSignoffExpectation(env)).toEqual({ valid: true });
  });

  it('a signoff block carrying sessionSeq counts as a session sign-off whatever its statement says', () => {
    const env = envelopeWith(null, {
      webauthnAssertion: assertionFor('x'),
      signoff: { statement: batchStatement, sessionSeq: 3 },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'session_signoff_not_expected' });
  });

  it('policy expectation, nothing carried: not final, signature_missing', () => {
    expect(checkSignoffExpectation(envelopeWith({ policyDigest: HEX_A }))).toEqual({
      valid: null,
      reason: 'signature_missing',
    });
  });

  it('policy expectation, a per-record signature over this record: true', () => {
    const env = envelopeWith({ policyDigest: HEX_A });
    env.nonRepudiation = { webauthnAssertion: assertionFor(webauthnChallengeForDigest(env.integrity.canonicalDigest)) };
    expect(checkSignoffExpectation(env)).toEqual({ valid: true });
  });

  it('policy expectation, an assertion about another record: signature_missing (an unbound assertion is no signature)', () => {
    const env = envelopeWith({ policyDigest: HEX_A }, {
      webauthnAssertion: assertionFor(webauthnChallengeForDigest(HEX_B)),
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: null, reason: 'signature_missing' });
  });

  it('policy expectation, a batch sign-off that covers the record: true', () => {
    const env = envelopeWith({ policyDigest: HEX_A });
    env.nonRepudiation = batchSignedBy(env.integrity.canonicalDigest) as EvidenceEnvelope['nonRepudiation'];
    expect(checkSignoffExpectation(env)).toEqual({ valid: true });
  });

  // A stripped signature swapped for junk must not read as the signature
  // being carried: every check that needs no key runs first.
  describe('policy expectation, a signoff block and assertion that do not bind as a batch sign-off of this record: false, signoff_unbound', () => {
    const cases: Array<[string, (digest: string) => Record<string, unknown>]> = [
      ['an empty signoff block beside an assertion', () => ({ webauthnAssertion: assertionFor('x'), signoff: {} })],
      ['a statement of mode batch alone, and an assertion whose clientDataJSON is {}', () => ({
        webauthnAssertion: { credentialId: 'x', authenticatorData: 'AA', clientDataJSON: 'e30', signature: 'AA' },
        signoff: { statement: { mode: 'batch' } },
      })],
      ['an assertion that presented another challenge', (d) => ({ ...batchSignedBy(d), webauthnAssertion: assertionFor('x') })],
      ['an assertion that presented the per-record challenge', (d) => ({
        ...batchSignedBy(d), webauthnAssertion: assertionFor(webauthnChallengeForDigest(d)),
      })],
      ['an assertion that is not a webauthn.get', (d) => {
        const signed = batchSignedBy(d);
        const challenge = signoffStatementChallenge(signoffStatementDigest(signed.signoff.statement)!);
        const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge })).toString('base64url');
        return { ...signed, webauthnAssertion: { ...signed.webauthnAssertion, clientDataJSON } };
      }],
      ['a tree that does not hold the record', () => batchSignedBy(HEX_A)],
      ['a proof that names another leaf', (d) => {
        const signed = batchSignedBy(d);
        return { ...signed, signoff: { ...signed.signoff, inclusion: { ...signed.signoff.inclusion, leafIndex: 1 } } };
      }],
      ['no inclusion proof', (d) => {
        const signed = batchSignedBy(d);
        return { ...signed, signoff: { statement: signed.signoff.statement } };
      }],
      ['a statement of mode record', (d) => batchSignedBy(d, (st) => { st.mode = 'record'; })],
      ['a statement treeSize past 2^53 - 1', (d) => batchSignedBy(d, (st) => { st.treeSize = 2 ** 53; })],
      ['a session statement relabelled as a batch one', () => ({
        webauthnAssertion: assertionFor(signoffStatementChallenge(sessionDigest)),
        signoff: { statement: { ...sessionStatement, mode: 'batch' } },
      })],
      ['a signoff that is not an object beside the per-record assertion', (d) => ({
        webauthnAssertion: assertionFor(webauthnChallengeForDigest(d)),
        signoff: 'batch',
      })],
    ];
    it.each(cases)('%s', (_name, carried) => {
      const env = envelopeWith({ policyDigest: HEX_A });
      env.nonRepudiation = carried(env.integrity.canonicalDigest) as EvidenceEnvelope['nonRepudiation'];
      expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'signoff_unbound' });
    });
  });

  it('policy expectation, the batch block with its assertion stripped: not final, signature_missing', () => {
    const env = envelopeWith({ policyDigest: HEX_A });
    env.nonRepudiation = { signoff: batchSignedBy(env.integrity.canonicalDigest).signoff } as EvidenceEnvelope['nonRepudiation'];
    expect(checkSignoffExpectation(env)).toEqual({ valid: null, reason: 'signature_missing' });
  });

  it('policy expectation, a session sign-off: false', () => {
    const env = envelopeWith({ policyDigest: HEX_A }, {
      webauthnAssertion: assertionFor('x'),
      signoff: { statement: sessionStatement, sessionSeq: 1 },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'session_signoff_not_expected' });
  });

  const sessionAssertion = () => assertionFor(signoffStatementChallenge(sessionDigest));

  it('session expectation, its own sign-off: true', () => {
    const env = envelopeWith({ statementDigest: sessionDigest, sessionSeq: 3 }, {
      webauthnAssertion: sessionAssertion(),
      signoff: { statement: sessionStatement, sessionSeq: 3 },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: true });
  });

  // A session record is written with its sign-off in the same write, so
  // missing sign-off material is a removal, never a record awaiting one.
  it('session expectation, the sign-off stripped: false, signoff_stripped', () => {
    expect(checkSignoffExpectation(envelopeWith({ statementDigest: sessionDigest, sessionSeq: 3 }))).toEqual({
      valid: false,
      reason: 'signoff_stripped',
    });
  });

  it('session expectation, a junk assertion beside its own sign-off block: false, signoff_unbound', () => {
    const env = envelopeWith({ statementDigest: sessionDigest, sessionSeq: 3 }, {
      webauthnAssertion: assertionFor('AAAA'),
      signoff: { statement: sessionStatement, sessionSeq: 3 },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'signoff_unbound' });
  });

  it.each([['the string "3"', '3'], ['the string " 3"', ' 3'], ['3.5', 3.5], ['true', true]])(
    'session expectation, the slot written as %s: false, session_seq_mismatch',
    (_name, seq) => {
      const env = envelopeWith({ statementDigest: sessionDigest, sessionSeq: seq === true ? 1 : 3 }, {
        webauthnAssertion: sessionAssertion(),
        signoff: { statement: sessionStatement, sessionSeq: seq },
      });
      expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'session_seq_mismatch' });
    },
  );

  it('session expectation, another session\'s statement: false', () => {
    const other = { ...sessionStatement, sessionId: '7f1c1f0e-8d6a-4f0e-9d6b-1a2b3c4d5e6f' };
    const env = envelopeWith({ statementDigest: sessionDigest, sessionSeq: 3 }, {
      webauthnAssertion: assertionFor('x'),
      signoff: { statement: other, sessionSeq: 3 },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'statement_digest_mismatch' });
  });

  it('session expectation, a batch sign-off in its place: false', () => {
    const env = envelopeWith({ statementDigest: sessionDigest, sessionSeq: 3 }, {
      webauthnAssertion: assertionFor('x'),
      signoff: { statement: batchStatement, inclusion: { leafIndex: 0, path: [] } },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'statement_digest_mismatch' });
  });

  it('session expectation, an unreadable signoff block: false', () => {
    const env = envelopeWith({ statementDigest: sessionDigest, sessionSeq: 3 }, {
      webauthnAssertion: assertionFor('x'),
      signoff: 'garbage',
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'statement_digest_mismatch' });
  });

  it('session expectation, another slot: false', () => {
    const env = envelopeWith({ statementDigest: sessionDigest, sessionSeq: 3 }, {
      webauthnAssertion: assertionFor('x'),
      signoff: { statement: sessionStatement, sessionSeq: 4 },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'session_seq_mismatch' });
  });

  it('session expectation, its sign-off without the assertion: false, signoff_stripped', () => {
    const env = envelopeWith({ statementDigest: sessionDigest, sessionSeq: 3 }, {
      signoff: { statement: sessionStatement, sessionSeq: 3 },
    });
    expect(checkSignoffExpectation(env)).toEqual({ valid: false, reason: 'signoff_stripped' });
  });

  it('a value of neither form in the payload: false', () => {
    expect(checkSignoffExpectation(envelopeWith({ policyDigest: HEX_A, extra: 1 }))).toEqual({
      valid: false,
      reason: 'malformed_signoff_expectation',
    });
    expect(checkSignoffExpectation(envelopeWith('required'))).toEqual({
      valid: false,
      reason: 'malformed_signoff_expectation',
    });
  });

  it('policy expectation, a stored digest that is empty: an assertion bound to it binds nothing', () => {
    const env = envelopeWith({ policyDigest: HEX_A }, { webauthnAssertion: assertionFor(webauthnChallengeForDigest('')) });
    env.integrity.canonicalDigest = '';
    expect(checkSignoffExpectation(env)).toEqual({ valid: null, reason: 'signature_missing' });
  });

  it.each([null, undefined, 5, 'x', [], { payload: 5 }, { payload: {}, nonRepudiation: 'x' }])(
    'never throws on untrusted input (%p)',
    (value) => {
      expect(() => checkSignoffExpectation(value)).not.toThrow();
    },
  );
});

describe('verifyEnvelope reports the expectation', () => {
  it('true on an ordinary record, with no reason', () => {
    const result = verifyEnvelope(assembleEnvelope(input));
    expect(result.signoffExpectationValid).toBe(true);
    expect(result).not.toHaveProperty('signoffExpectationReason');
  });

  it('a stripped signature: verified stays true (the record is intact), signature_missing is reported', () => {
    const env = envelopeWith({ policyDigest: HEX_A });
    const result = verifyEnvelope(env);
    expect(result.verified).toBe(true);
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('signature_missing');
  });

  it('a transplanted session sign-off is false from the record alone', () => {
    const env = envelopeWith(null, {
      webauthnAssertion: assertionFor('x'),
      signoff: { statement: sessionStatement, sessionSeq: 1 },
    });
    const result = verifyEnvelope(env);
    expect(result.signoffExpectationValid).toBe(false);
    expect(result.signoffExpectationReason).toBe('session_signoff_not_expected');
  });

  // The expectation is authenticated only by the digest recomputed over it.
  // A record whose digest does not recompute carries an expectation anyone
  // could have written, so it is not read: null, digest_invalid, as
  // verifyBundle blocks signoff.expectation on record.digest.
  it('the expectation tamper (an owed signature stripped and { policyDigest } rewritten to null) is null, digest_invalid, never true', () => {
    const env = envelopeWith({ policyDigest: HEX_A });
    expect(verifyEnvelope(env).signoffExpectationReason).toBe('signature_missing');
    env.payload.signoffExpectation = null;
    expect(checkSignoffExpectation(env)).toEqual({ valid: true });
    const result = verifyEnvelope(env);
    expect(result.verified).toBe(false);
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('digest_invalid');
  });

  it('a per-record signature still carried does not make a rewritten expectation read true', () => {
    const env = envelopeWith({ policyDigest: HEX_A });
    env.nonRepudiation = { webauthnAssertion: assertionFor(webauthnChallengeForDigest(env.integrity.canonicalDigest)) } as EvidenceEnvelope['nonRepudiation'];
    expect(verifyEnvelope(env).signoffExpectationValid).toBe(true);
    env.payload.signoffExpectation = null;
    const result = verifyEnvelope(env);
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('digest_invalid');
  });

  it('a session record whose expectation was nulled is digest_invalid, not a finding read off the forged value', () => {
    const env = envelopeWith(
      { statementDigest: signoffStatementDigest(sessionStatement)!, sessionSeq: 1 },
      {
        webauthnAssertion: assertionFor(signoffStatementChallenge(signoffStatementDigest(sessionStatement)!)),
        signoff: { statement: sessionStatement, sessionSeq: 1 },
      },
    );
    expect(verifyEnvelope(env).signoffExpectationValid).toBe(true);
    env.payload.signoffExpectation = null;
    const result = verifyEnvelope(env);
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('digest_invalid');
  });

  it('any other payload edit under the stored digest is digest_invalid too', () => {
    const env = envelopeWith(null);
    env.payload.reason = 'edited';
    const result = verifyEnvelope(env);
    expect(result.verified).toBe(false);
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('digest_invalid');
  });

  it('an unknown schema version is digest_invalid: no digest recomputes', () => {
    const env = envelopeWith({ policyDigest: HEX_A });
    env.payload.schemaVersion = 'v9';
    const result = verifyEnvelope(env);
    expect(result.schemaValid).toBe(false);
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('digest_invalid');
  });

  it('a payload that cannot be serialized is digest_invalid', () => {
    const env = envelopeWith(null);
    env.payload.reason = 'lone \ud800 surrogate';
    const result = verifyEnvelope(env);
    expect(result.payloadSerializationError).toBeDefined();
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('digest_invalid');
  });

  it('the async descriptor path reports the same', async () => {
    const env = envelopeWith({ policyDigest: HEX_A });
    env.payload.signoffExpectation = null;
    const storage = { getModelDescriptor: async () => null } as never;
    const result = await verifyEnvelope(env, undefined, undefined, { storage });
    expect(result.signoffExpectationValid).toBeNull();
    expect(result.signoffExpectationReason).toBe('digest_invalid');
  });
});

describe('store generations (Record §4.1)', () => {
  /** A record as a 0.7 release wrote it: the nine-name set, `humanAction`, `humanReason` and a top-level `aiBom`. */
  function record07(): EvidenceEnvelope {
    const payload = {
      evidenceId: '6f1c1f0e-8d6a-4f0e-9d6b-1a2b3c4d5e70', schemaVersion: 'v1.0', aiSystemId: 'sys', aiOutput: { r: 'approve' },
      humanAction: 'approved', humanReason: 'ok', capturedAt: '2026-09-01T10:00:00.000Z', sequenceNumber: 1, aiBom: null,
      signoffExpectation: null,
    };
    return {
      envelopeVersion: 'e1', payload: payload as never,
      integrity: { canonicalDigest: computeDigest(canonicalSerialize(payload, [...FIELD_SET_0_7])), chainLink: null },
      nonRepudiation: {}, custodyChain: [], attestationStatus: 'none',
    };
  }

  /** A record as a release before 0.7.0 wrote it: the eight-name set, no `signoffExpectation` key. */
  function recordBefore07(): EvidenceEnvelope {
    const env = record07();
    delete (env.payload as Partial<EvidenceEnvelope['payload']>).signoffExpectation;
    env.integrity.canonicalDigest = computeDigest(
      canonicalSerialize(env.payload as unknown as Record<string, unknown>, [...FIELD_SET_BEFORE_0_7]),
    );
    return env;
  }

  it('names the generation each record recomputes under, never trusting schemaVersion', () => {
    expect(recordFieldSetGeneration(assembleEnvelope(input))).toBe('0.8');
    expect(recordFieldSetGeneration(record07())).toBe('0.7');
    expect(recordFieldSetGeneration(recordBefore07())).toBe('before-0.7');
    const tampered = assembleEnvelope(input);
    tampered.payload.reason = 'rewritten';
    expect(recordFieldSetGeneration(tampered)).toBeNull();
  });

  it('reports a 0.7 record as digest_mismatch with the fieldSet fact, which explains and never excuses', () => {
    const result = verifyEnvelope(record07());
    expect(result.verified).toBe(false);
    expect(result.fieldSet).toBe('0.7');
    expect(result.signoffExpectationReason).toBe('digest_invalid');
    expect(verifyEnvelope(recordBefore07()).fieldSet).toBe('before-0.7');
    expect(verifyEnvelope(assembleEnvelope(input))).not.toHaveProperty('fieldSet');
    expect(earlierFieldSet(record07().payload, 'ab'.repeat(32))).toBeNull();
  });

  it('a 0.8 record rewritten into the 0.7 field set reads as a 0.7 record, and is still a digest mismatch', () => {
    const env = assembleEnvelope(input);
    const rewritten = { ...env.payload, humanAction: 'approved', humanReason: 'rewritten', aiBom: null } as Record<string, unknown>;
    env.payload = rewritten as never;
    env.integrity.canonicalDigest = computeDigest(canonicalSerialize(rewritten, [...FIELD_SET_0_7]));
    const result = verifyEnvelope(env);
    expect(result.verified).toBe(false);
    expect(result.fieldSet).toBe('0.7');
    expect(result.unhashedPayloadMembers).toEqual(['aiBom', 'humanAction', 'humanReason']);
  });

  it('recordPredatesSignoffExpectation recognises only a record before 0.7.0', () => {
    expect(recordPredatesSignoffExpectation(recordBefore07())).toBe(true);
    expect(recordPredatesSignoffExpectation(record07())).toBe(false);
    expect(recordPredatesSignoffExpectation(assembleEnvelope(input))).toBe(false);
    const altered = recordBefore07();
    (altered.payload as unknown as Record<string, unknown>).humanReason = 'rewritten';
    expect(recordPredatesSignoffExpectation(altered)).toBe(false);
  });

  it.each([null, 5, {}, { payload: {}, integrity: {} }, { payload: { aiOutput: {} }, integrity: { canonicalDigest: 5 } }])(
    'never throws (%p)',
    (value) => {
      expect(recordPredatesSignoffExpectation(value)).toBe(false);
      expect(recordFieldSetGeneration(value)).toBeNull();
    },
  );

  it('StoreSchemaOutdatedError names the record, the generation, and tells the operator to create a new store', () => {
    const err = new StoreSchemaOutdatedError('ev-1');
    expect(err.code).toBe('store_schema_outdated');
    expect(err.retryable).toBe(false);
    expect(err.evidenceId).toBe('ev-1');
    expect(err.generation).toBe('before-0.7');
    expect(err.message).toMatch(/before 0\.7\.0/);
    expect(err.message).toMatch(/Create a new store/);
    const err07 = new StoreSchemaOutdatedError('ev-2', '0.7');
    expect(err07.generation).toBe('0.7');
    expect(err07.message).toMatch(/0\.7 line/);
  });
});
