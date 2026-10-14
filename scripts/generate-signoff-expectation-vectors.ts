/**
 * Generate vectors/signoff-expectation-vectors.json: the answers every
 * implementation of `payload.signoffExpectation` (Record §9, Verification §5;
 * the mandate form, Record §9.1 and §9.6) must give, over records of the v1.0
 * hashed field set as revised in 0.8.0, in five parts:
 *
 *   - shapes            a value, and why it is not a signoff expectation (or
 *                       `null` when it is one): the rule a capture applies;
 *                       the four forms, the mandate form's member rules
 *                       (`invalid_mandate_assertion`, `invalid_mandate_seq`,
 *                       `invalid_totals`, `invalid_confirm`) and mixed members;
 *   - statementDigests  a sign-off statement, its digest (lowercase hex
 *                       SHA-256 of its canonical bytes, or `null` for a
 *                       statement Record §9.4 gives no digest), and
 *                       the WebAuthn challenge a ceremony over it presents;
 *   - checks            a whole envelope, and what the expectation check says
 *                       about it (`valid`, and `reason` unless it is `true`),
 *                       including row 1a (a mandate block under another
 *                       form) and rows 17 to 24 (the mandate form against its
 *                       mandate block and confirmation);
 *   - predates          a whole envelope, and whether it is a record a release
 *                       before 0.7.0 captured (the rule `Tzun.init()` refuses a
 *                       store by);
 *   - verifications     a whole envelope (a genesis record), and what a
 *                       verifier reports for it: whether it verifies, and the
 *                       expectation check, which is read only when the digest
 *                       recomputes (`null`, `digest_invalid` otherwise), as
 *                       `verifyEnvelope`, a read's verdict and the Python
 *                       SDK's `verify()` report it.
 *
 *   pnpm exec tsx scripts/generate-signoff-expectation-vectors.ts > vectors/signoff-expectation-vectors.json
 *
 * The expected answers are written here from the rules, case by case, not
 * read off the engine. The script then runs the engine over every case and
 * stops if it disagrees. The TS suite (tests/ts/signoff-expectation-vectors.test.ts)
 * and the Python suite (python/tests/verify/test_signoff_expectation_vectors.py)
 * hold both SDKs to the file.
 */
import { createHash } from 'node:crypto';
import {
  FIELD_SET_0_7,
  FIELD_SET_BEFORE_0_7,
  buildMerkleTree,
  canonicalSerialize,
  determineAttestationStatus,
  checkSignoffExpectation,
  computeDigest,
  getMerkleProof,
  getMerkleRoot,
  recordPredatesSignoffExpectation,
  recordVerdict,
  SchemaRegistry,
  signoffExpectationViolation,
  signoffStatementChallenge,
  signoffStatementDigest,
  verifyEnvelope,
  webauthnChallengeForDigest,
  type EvidenceEnvelope,
} from '@tzun/engine';
import {
  W4_ASSERTION,
  W4_ASSERTION_DIGEST,
  W4_BLOCK,
  W4_CHALLENGE,
  W4_DOCUMENT,
  W4_STATEMENT,
  agentDecider,
  assertionDigestOf,
  assertionPresenting,
  confirmationChallengeOf,
  digestOf,
  payload,
  signedAssertion,
} from './generate-vectors-shared';

const V1_0 = new SchemaRegistry().get('v1.0')!.hashedFieldSet;
const POLICY = createHash('sha256').update('vector policy').digest('hex');
const OTHER = createHash('sha256').update('another digest').digest('hex');

const decision = {
  aiOutput: { recommendation: 'approve', score: 0.82 },
  action: 'approved',
  reason: 'Reviewed',
  aiSystemId: 'vectors',
};

const sessionStatement = {
  v: 'tzun-signoff/1', mode: 'session', sessionId: '3b8f0c2e-5d1a-4c6e-9f2b-7a1d4e5c6b8a', signer: 'user-17',
  signerName: 'Sm9zw6kgw4FsdmFyZXo', meaning: 'approval', policyDigest: POLICY, notBefore: 'none',
  openedAt: '2026-09-26T09:00:00.000Z', maxAgeMs: 1800000, maxRecords: 50,
};
const batchStatement = {
  v: 'tzun-signoff/1', mode: 'batch', batchId: '9d2c7e41-0b6a-4f3d-8e5c-2a1b3c4d5e6f', signer: 'user-17',
  signerName: 'Sm9zw6kgw4FsdmFyZXo', meaning: 'approval', policyDigest: POLICY, notBefore: 'none',
  merkleSpec: 'rfc6962', root: OTHER, treeSize: 2,
};
/** Lowercase hex SHA-256 of a statement's canonical bytes, computed here rather than by the engine. */
function statementDigestOf(statement: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalSerialize(statement, Object.keys(statement))).digest('hex');
}
/** base64url_nopad(SHA-256("tzun-signoff-v1" || statementDigest)), computed here (Record §9.4). */
function statementChallengeOf(statementDigest: string): string {
  return createHash('sha256').update('tzun-signoff-v1' + statementDigest).digest('base64url');
}
const SESSION = statementDigestOf(sessionStatement);
/** The mandate form of the worked example W6, W4's assertion digest, no caps. */
const MANDATE_FORM = { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: null, confirm: false };

/** An assertion whose clientDataJSON presents `challenge`. The signature is not a real one: nothing here verifies it. */
function assertion(challenge: string) {
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://example.test' }))
    .toString('base64url');
  return { signature: 'c2lnbmF0dXJl', credentialKeyId: 'credential-1', algorithm: 'ES256', clientDataJSON };
}
/** The session ceremony's assertion: it presented the session statement's challenge. */
const sessionAssertion = () => assertion(statementChallengeOf(SESSION));

/**
 * A batch sign-off covering the record whose digest is `digest`: a two-record
 * batch tree over `[digest, OTHER]`, its statement naming that root and size,
 * the record at leaf 0, and an assertion that presented the statement's
 * challenge. `edit` changes the statement before its digest and challenge are
 * taken.
 */
function batchSignoffFor(digest: string, edit: (s: Record<string, unknown>) => void = () => {}) {
  const tree = buildMerkleTree([digest, OTHER]);
  const statement: Record<string, unknown> = { ...batchStatement, root: getMerkleRoot(tree), treeSize: 2 };
  edit(statement);
  return {
    statement,
    inclusion: { leafIndex: 0, path: getMerkleProof(tree, 0) },
    assertion: assertion(statementChallengeOf(statementDigestOf(statement))),
  };
}
function batchSignedBy(digest: string, edit?: (s: Record<string, unknown>) => void) {
  const b = batchSignoffFor(digest, edit);
  return { webauthnAssertion: b.assertion, signoff: { statement: b.statement, inclusion: b.inclusion } };
}

let seq = 0;
/**
 * A genesis record under the v1.0 rules as revised in 0.8.0, carrying
 * `expectation` and `nonRepudiation`: a human's decision, or `edit`'s. It is
 * not held to the writer's rules: a reader's vectors hold records a writer
 * refuses (a mandate form with no mandate link, for one).
 */
function record(
  expectation: unknown,
  nonRepudiation: (digest: string) => Record<string, unknown> = () => ({}),
  edit: Record<string, unknown> = {},
): EvidenceEnvelope {
  seq++;
  const p = payload({
    ...decision,
    evidenceId: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`,
    capturedAt: new Date(Date.parse('2026-09-26T10:00:00.000Z') + seq * 1000).toISOString(),
    signoffExpectation: expectation,
    ...edit,
  });
  const digest = computeDigest(canonicalSerialize(p, V1_0));
  const nr = nonRepudiation(digest);
  return {
    envelopeVersion: 'e1',
    payload: p,
    integrity: { canonicalDigest: digest, chainLink: null },
    nonRepudiation: nr,
    custodyChain: [],
    attestationStatus: determineAttestationStatus(nr as EvidenceEnvelope['nonRepudiation'], digest),
  } as unknown as EvidenceEnvelope;
}

const shapes: Array<{ case: string; value: unknown; violation: string | null }> = [
  { case: 'null: none expected', value: null, violation: null },
  { case: 'the policy form', value: { policyDigest: POLICY }, violation: null },
  { case: 'the session form', value: { statementDigest: SESSION, sessionSeq: 1 }, violation: null },
  { case: 'the session form at slot 2^53 - 1', value: { statementDigest: SESSION, sessionSeq: 9007199254740991 }, violation: null },
  { case: 'a string', value: 'required', violation: 'not_an_object' },
  { case: 'an array', value: [POLICY], violation: 'not_an_object' },
  { case: 'a number', value: 1, violation: 'not_an_object' },
  { case: 'false', value: false, violation: 'not_an_object' },
  { case: 'an empty object', value: {}, violation: 'unknown_members' },
  { case: 'an unknown member beside policyDigest', value: { policyDigest: POLICY, note: 'x' }, violation: 'unknown_members' },
  { case: 'both forms at once', value: { policyDigest: POLICY, statementDigest: SESSION, sessionSeq: 1 }, violation: 'unknown_members' },
  { case: 'statementDigest without sessionSeq', value: { statementDigest: SESSION }, violation: 'unknown_members' },
  { case: 'sessionSeq without statementDigest', value: { sessionSeq: 1 }, violation: 'unknown_members' },
  { case: 'a misspelt member', value: { policydigest: POLICY }, violation: 'unknown_members' },
  { case: 'an uppercase policy digest', value: { policyDigest: POLICY.toUpperCase() }, violation: 'invalid_policy_digest' },
  { case: 'a 63-character policy digest', value: { policyDigest: POLICY.slice(1) }, violation: 'invalid_policy_digest' },
  { case: 'a 65-character policy digest', value: { policyDigest: POLICY + '0' }, violation: 'invalid_policy_digest' },
  { case: 'a policy digest with a trailing newline', value: { policyDigest: POLICY + '\n' }, violation: 'invalid_policy_digest' },
  { case: 'a 0x-prefixed policy digest', value: { policyDigest: '0x' + POLICY }, violation: 'invalid_policy_digest' },
  { case: 'a null policy digest', value: { policyDigest: null }, violation: 'invalid_policy_digest' },
  { case: 'a sha256:-prefixed statement digest', value: { statementDigest: 'sha256:' + SESSION, sessionSeq: 1 }, violation: 'invalid_statement_digest' },
  { case: 'a numeric statement digest', value: { statementDigest: 7, sessionSeq: 1 }, violation: 'invalid_statement_digest' },
  { case: 'slot 0', value: { statementDigest: SESSION, sessionSeq: 0 }, violation: 'invalid_session_seq' },
  { case: 'a negative slot', value: { statementDigest: SESSION, sessionSeq: -3 }, violation: 'invalid_session_seq' },
  { case: 'a fractional slot', value: { statementDigest: SESSION, sessionSeq: 2.5 }, violation: 'invalid_session_seq' },
  { case: 'a string slot', value: { statementDigest: SESSION, sessionSeq: '2' }, violation: 'invalid_session_seq' },
  { case: 'a boolean slot', value: { statementDigest: SESSION, sessionSeq: true }, violation: 'invalid_session_seq' },
  { case: 'slot 2^53, past the safe integers', value: { statementDigest: SESSION, sessionSeq: 9007199254740992 }, violation: 'invalid_session_seq' },
  { case: 'the mandate form', value: MANDATE_FORM, violation: null },
  { case: 'the mandate form with totals and confirm true', value: { ...MANDATE_FORM, totals: { paid: 5230000, refunds: 0 }, confirm: true }, violation: null },
  { case: 'the mandate form, members supplied unsorted', value: { totals: null, confirm: false, mandateSeq: 41, mandateAssertion: W4_ASSERTION_DIGEST }, violation: null },
  { case: 'the mandate form at slot 2^53 - 1', value: { ...MANDATE_FORM, mandateSeq: 9007199254740991 }, violation: null },
  { case: 'the mandate form with 16 caps', value: { ...MANDATE_FORM, totals: Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`cap${String(i).padStart(2, '0')}`, i])) }, violation: null },
  { case: 'the mandate form without confirm', value: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: null }, violation: 'unknown_members' },
  { case: 'the mandate form beside policyDigest', value: { ...MANDATE_FORM, policyDigest: POLICY }, violation: 'unknown_members' },
  { case: 'the mandate form beside sessionSeq', value: { ...MANDATE_FORM, sessionSeq: 1 }, violation: 'unknown_members' },
  { case: 'an uppercase mandateAssertion', value: { ...MANDATE_FORM, mandateAssertion: W4_ASSERTION_DIGEST.toUpperCase() }, violation: 'invalid_mandate_assertion' },
  { case: 'a prefixed mandateAssertion', value: { ...MANDATE_FORM, mandateAssertion: `sha256:${W4_ASSERTION_DIGEST}` }, violation: 'invalid_mandate_assertion' },
  { case: 'mandateSeq 0', value: { ...MANDATE_FORM, mandateSeq: 0 }, violation: 'invalid_mandate_seq' },
  { case: 'a fractional mandateSeq', value: { ...MANDATE_FORM, mandateSeq: 41.5 }, violation: 'invalid_mandate_seq' },
  { case: 'a string mandateSeq', value: { ...MANDATE_FORM, mandateSeq: '41' }, violation: 'invalid_mandate_seq' },
  { case: 'a boolean mandateSeq', value: { ...MANDATE_FORM, mandateSeq: true }, violation: 'invalid_mandate_seq' },
  { case: 'mandateSeq 2^53', value: { ...MANDATE_FORM, mandateSeq: 9007199254740992 }, violation: 'invalid_mandate_seq' },
  { case: 'totals {} (write null)', value: { ...MANDATE_FORM, totals: {} }, violation: 'invalid_totals' },
  { case: 'totals with 17 caps', value: { ...MANDATE_FORM, totals: Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`cap${String(i).padStart(2, '0')}`, i])) }, violation: 'invalid_totals' },
  { case: 'a cap name with a space', value: { ...MANDATE_FORM, totals: { 'paid total': 1 } }, violation: 'invalid_totals' },
  { case: 'a total that is a string', value: { ...MANDATE_FORM, totals: { paid: '3' } }, violation: 'invalid_totals' },
  { case: 'a negative total', value: { ...MANDATE_FORM, totals: { paid: -1 } }, violation: 'invalid_totals' },
  { case: 'totals that are an array', value: { ...MANDATE_FORM, totals: [1] }, violation: 'invalid_totals' },
  { case: 'confirm written 1', value: { ...MANDATE_FORM, confirm: 1 }, violation: 'invalid_confirm' },
  { case: 'confirm written "false"', value: { ...MANDATE_FORM, confirm: 'false' }, violation: 'invalid_confirm' },
  { case: 'confirm null', value: { ...MANDATE_FORM, confirm: null }, violation: 'invalid_confirm' },
];

const statementDigests: Array<{ case: string; statement: unknown; digest: string | null }> = [
  { case: 'a session statement', statement: sessionStatement, digest: SESSION },
  {
    case: 'a batch statement, members supplied unsorted',
    statement: { treeSize: 2, root: OTHER, mode: 'batch', ...batchStatement },
    digest: statementDigestOf(batchStatement),
  },
  {
    case: 'an integer at 2^53 - 1, the largest safe one',
    statement: { ...sessionStatement, maxRecords: 9007199254740991 },
    digest: statementDigestOf({ ...sessionStatement, maxRecords: 9007199254740991 }),
  },
  // Record §9.4 gives a digest only to a statement of printable-ASCII strings
  // and non-negative safe integers; anything else has no digest.
  { case: 'an integer past 2^53 - 1', statement: { ...sessionStatement, maxRecords: 9007199254740992 }, digest: null },
  { case: 'a negative integer', statement: { ...sessionStatement, maxRecords: -1 }, digest: null },
  { case: 'a fraction', statement: { ...sessionStatement, maxAgeMs: 1.5 }, digest: null },
  { case: 'a boolean', statement: { ...sessionStatement, maxRecords: true }, digest: null },
  { case: 'a null member', statement: { ...sessionStatement, notBefore: null }, digest: null },
  { case: 'a nested object', statement: { ...sessionStatement, signer: { id: 'user-17' } }, digest: null },
  { case: 'an array member', statement: { ...sessionStatement, signer: ['user-17'] }, digest: null },
  { case: 'a string outside printable ASCII', statement: { ...sessionStatement, signer: 'Jos\u00e9' }, digest: null },
  { case: 'a control character in a string', statement: { ...sessionStatement, signer: 'user-17\n' }, digest: null },
  { case: 'a key outside printable ASCII', statement: { ...sessionStatement, 'sign\u00e9r': 'user-17' }, digest: null },
  { case: 'a string, not an object', statement: 'tzun-signoff/1', digest: null },
  { case: 'an array, not an object', statement: [sessionStatement], digest: null },
];

/** A session statement holding an integer past 2^53 - 1, and the digest a reader that rounded it would take. */
const unsafeSession = { ...sessionStatement, maxRecords: 9007199254740992 };
const UNSAFE_SESSION = statementDigestOf(unsafeSession);

const checks: Array<{ case: string; envelope: EvidenceEnvelope; expect: { valid: boolean | null; reason?: string } }> = [
  { case: 'null, nothing carried', envelope: record(null), expect: { valid: true } },
  {
    case: 'null, a per-record signature nobody required',
    envelope: record(null, (d) => ({ webauthnAssertion: assertion(webauthnChallengeForDigest(d)) })),
    expect: { valid: true },
  },
  {
    case: 'null, a batch sign-off nobody required',
    envelope: record(null, (d) => batchSignedBy(d)),
    expect: { valid: true },
  },
  {
    case: 'null, a session sign-off transplanted onto it',
    envelope: record(null, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: 4 } })),
    expect: { valid: false, reason: 'session_signoff_not_expected' },
  },
  {
    case: 'null, a signoff block carrying sessionSeq beside a batch statement',
    envelope: record(null, () => ({ webauthnAssertion: assertion('x'), signoff: { statement: batchStatement, sessionSeq: 4 } })),
    expect: { valid: false, reason: 'session_signoff_not_expected' },
  },
  // Nothing is owed, but a sign-off that is carried must bind: a session
  // sign-off relabelled as a batch one, or a batch sign-off lifted from a
  // batch that does not hold the record, is not one of this record.
  {
    case: 'null, a session sign-off relabelled as a batch one (mode batch, sessionSeq dropped)',
    envelope: record(null, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: { ...sessionStatement, mode: 'batch' } } })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'null, a batch sign-off lifted from a batch that does not hold this record',
    envelope: record(null, () => batchSignedBy(POLICY)),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'null, an empty signoff block and an assertion',
    envelope: record(null, () => ({ webauthnAssertion: assertion('AAAA'), signoff: {} })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'null, a signoff that is not an object beside an assertion',
    envelope: record(null, (d) => ({ webauthnAssertion: assertion(webauthnChallengeForDigest(d)), signoff: 'batch' })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'null, a batch signoff block without an assertion (no sign-off is carried)',
    envelope: record(null, (d) => ({ signoff: batchSignedBy(d).signoff })),
    expect: { valid: true },
  },
  { case: 'policy, nothing carried (awaiting sign-off, or stripped)', envelope: record({ policyDigest: POLICY }), expect: { valid: null, reason: 'signature_missing' } },
  {
    case: 'policy, a per-record signature over this record',
    envelope: record({ policyDigest: POLICY }, (d) => ({ webauthnAssertion: assertion(webauthnChallengeForDigest(d)) })),
    expect: { valid: true },
  },
  {
    case: 'policy, an assertion about another record',
    envelope: record({ policyDigest: POLICY }, () => ({ webauthnAssertion: assertion(webauthnChallengeForDigest(OTHER)) })),
    expect: { valid: null, reason: 'signature_missing' },
  },
  {
    case: 'policy, an assertion with no clientDataJSON',
    envelope: record({ policyDigest: POLICY }, () => ({ webauthnAssertion: { signature: 'c2ln', credentialKeyId: 'c', algorithm: 'ES256' } })),
    expect: { valid: null, reason: 'signature_missing' },
  },
  {
    case: 'policy, a batch sign-off that covers this record',
    envelope: record({ policyDigest: POLICY }, (d) => batchSignedBy(d)),
    expect: { valid: true },
  },
  {
    case: 'policy, a batch sign-off whose assertion presented another challenge',
    envelope: record({ policyDigest: POLICY }, (d) => ({ ...batchSignedBy(d), webauthnAssertion: assertion('batch') })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a batch signoff block beside a per-record signature over this record',
    envelope: record({ policyDigest: POLICY }, (d) => ({ ...batchSignedBy(d), webauthnAssertion: assertion(webauthnChallengeForDigest(d)) })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a batch sign-off whose tree does not hold this record',
    envelope: record({ policyDigest: POLICY }, () => batchSignedBy(POLICY)),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a batch sign-off whose proof names another leaf',
    envelope: record({ policyDigest: POLICY }, (d) => {
      const signed = batchSignedBy(d);
      return { ...signed, signoff: { ...signed.signoff, inclusion: { ...signed.signoff.inclusion, leafIndex: 1 } } };
    }),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a batch sign-off with no inclusion proof',
    envelope: record({ policyDigest: POLICY }, (d) => {
      const signed = batchSignedBy(d);
      return { ...signed, signoff: { statement: signed.signoff.statement } };
    }),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a batch statement whose treeSize is past 2^53 - 1',
    envelope: record({ policyDigest: POLICY }, (d) => batchSignedBy(d, (st) => { st.treeSize = 9007199254740992; })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, junk in place of a stripped signature: an empty signoff block and an assertion',
    envelope: record({ policyDigest: POLICY }, () => ({ webauthnAssertion: assertion('AAAA'), signoff: {} })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, junk in place of a stripped signature: a statement of mode batch alone and an assertion whose clientDataJSON is {}',
    envelope: record({ policyDigest: POLICY }, () => ({
      webauthnAssertion: { signature: 'AA', credentialKeyId: 'x', algorithm: 'ES256', clientDataJSON: 'e30' },
      signoff: { statement: { mode: 'batch' } },
    })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a batch signoff block whose assertion was stripped',
    envelope: record({ policyDigest: POLICY }, (d) => ({ signoff: batchSignedBy(d).signoff })),
    expect: { valid: null, reason: 'signature_missing' },
  },
  {
    case: 'policy, a session sign-off relabelled as a batch one (mode batch, sessionSeq dropped)',
    envelope: record({ policyDigest: POLICY }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: { ...sessionStatement, mode: 'batch' } } })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a batch sign-off relabelled as a record one',
    envelope: record({ policyDigest: POLICY }, (d) => {
      const signed = batchSignedBy(d);
      return { ...signed, signoff: { ...signed.signoff, statement: { ...signed.signoff.statement, mode: 'record' } } };
    }),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a signoff that is not an object beside a per-record signature over this record',
    envelope: record({ policyDigest: POLICY }, (d) => ({ webauthnAssertion: assertion(webauthnChallengeForDigest(d)), signoff: 'batch' })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'policy, a session sign-off',
    envelope: record({ policyDigest: POLICY }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: 1 } })),
    expect: { valid: false, reason: 'session_signoff_not_expected' },
  },
  {
    case: 'session, its own sign-off',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: 4 } })),
    expect: { valid: true },
  },
  { case: 'session, the sign-off stripped', envelope: record({ statementDigest: SESSION, sessionSeq: 4 }), expect: { valid: false, reason: 'signoff_stripped' } },
  {
    case: 'session, its sign-off without the assertion',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ signoff: { statement: sessionStatement, sessionSeq: 4 } })),
    expect: { valid: false, reason: 'signoff_stripped' },
  },
  {
    case: 'session, its sign-off beside an assertion from another ceremony',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: assertion('AAAA'), signoff: { statement: sessionStatement, sessionSeq: 4 } })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'session, its sign-off beside an assertion with no clientDataJSON',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({
      webauthnAssertion: { signature: 'c2ln', credentialKeyId: 'c', algorithm: 'ES256' },
      signoff: { statement: sessionStatement, sessionSeq: 4 },
    })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'session, its sign-off beside the per-record assertion over this record',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, (d) => ({
      webauthnAssertion: assertion(webauthnChallengeForDigest(d)),
      signoff: { statement: sessionStatement, sessionSeq: 4 },
    })),
    expect: { valid: false, reason: 'signoff_unbound' },
  },
  {
    case: 'session, another session\'s statement',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({
      webauthnAssertion: sessionAssertion(),
      signoff: { statement: { ...sessionStatement, sessionId: '4c9f1d3f-6e2b-4d7f-8a3c-8b2e5f6d7c9b' }, sessionSeq: 4 },
    })),
    expect: { valid: false, reason: 'statement_digest_mismatch' },
  },
  {
    case: 'session, a statement holding an integer past 2^53 - 1 (it has no digest)',
    envelope: record({ statementDigest: UNSAFE_SESSION, sessionSeq: 4 }, () => ({
      webauthnAssertion: assertion(statementChallengeOf(UNSAFE_SESSION)),
      signoff: { statement: unsafeSession, sessionSeq: 4 },
    })),
    expect: { valid: false, reason: 'statement_digest_mismatch' },
  },
  {
    case: 'session, a batch sign-off in its place',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, (d) => batchSignedBy(d)),
    expect: { valid: false, reason: 'statement_digest_mismatch' },
  },
  {
    case: 'session, a signoff block with no statement',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { sessionSeq: 4 } })),
    expect: { valid: false, reason: 'statement_digest_mismatch' },
  },
  {
    case: 'session, a signoff that is not an object',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: 'session' })),
    expect: { valid: false, reason: 'statement_digest_mismatch' },
  },
  {
    case: 'session, another slot',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: 5 } })),
    expect: { valid: false, reason: 'session_seq_mismatch' },
  },
  // A reader that coerces a JSON string or boolean to a number would take
  // these for the slot the record names.
  {
    case: 'session, its slot written as the string "4"',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: '4' } })),
    expect: { valid: false, reason: 'session_seq_mismatch' },
  },
  {
    case: 'session, its slot written as the string " 4"',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: ' 4' } })),
    expect: { valid: false, reason: 'session_seq_mismatch' },
  },
  {
    case: 'session, slot 1 written as true',
    envelope: record({ statementDigest: SESSION, sessionSeq: 1 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: true } })),
    expect: { valid: false, reason: 'session_seq_mismatch' },
  },
  { case: 'an expectation of neither form', envelope: record({ policyDigest: POLICY, by: 'x' }), expect: { valid: false, reason: 'malformed_signoff_expectation' } },
  { case: 'an expectation that is a string', envelope: record('required'), expect: { valid: false, reason: 'malformed_signoff_expectation' } },
];

// ── the mandate form (Record §9.1, §9.6; Verification §5: row 1a and rows 17 to 24) ──

/** A decision under a mandate, as a reader reads it: the agent-mandated decider and its mandate link. */
const UNDER_MANDATE = {
  decider: agentDecider('agent-mandated'),
  links: [{ rel: 'mandate', target: { digest: digestOf('issuance record'), evidenceId: null, locator: null }, attrs: null }],
};
const mandated = (expectation: Record<string, unknown>, nr: (digest: string) => Record<string, unknown> = () => ({})) =>
  record(expectation, nr, UNDER_MANDATE);
const block = (edit: Record<string, unknown> = {}) => ({ ...W4_BLOCK, ...edit });
/** An assertion that presents another ceremony's challenge, and a mandate form naming its digest. */
const elsewhere = assertionPresenting('AAAA');
/** A statement signed by someone other than the document's principal, and an assertion over it. */
const foreignStatement = { ...W4_STATEMENT, signer: 'user-9999' };
const foreignChallenge = statementChallengeOf(statementDigestOf(foreignStatement));
const foreignAssertion = assertionPresenting(foreignChallenge);
checks.push(
  { case: 'row 1a: null, a mandate block carried', envelope: record(null, () => ({ mandate: block() })), expect: { valid: false, reason: 'mandate_not_expected' } },
  { case: 'row 1a: policy, a mandate block beside a per-record signature', envelope: record({ policyDigest: POLICY }, (d) => ({ webauthnAssertion: assertion(webauthnChallengeForDigest(d)), mandate: block() })), expect: { valid: false, reason: 'mandate_not_expected' } },
  {
    case: 'row 1a: session, its own sign-off and a mandate block (row 1a is tried first)',
    envelope: record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: 4 }, mandate: block() })),
    expect: { valid: false, reason: 'mandate_not_expected' },
  },
  {
    case: 'policy, a per-record signature and issuance material (read by the mandate.issuance row, not row 1a)',
    envelope: record({ policyDigest: POLICY }, (d) => ({ webauthnAssertion: assertion(webauthnChallengeForDigest(d)), mandateIssuance: block() })),
    expect: { valid: true },
  },
  { case: 'row 24: the mandate form with its mandate block', envelope: mandated(MANDATE_FORM, () => ({ mandate: block() })), expect: { valid: true } },
  { case: 'row 24: the mandate block without its document (the scope row reports it missing)', envelope: mandated(MANDATE_FORM, () => ({ mandate: { statement: W4_STATEMENT, assertion: W4_ASSERTION, assertionTimestamp: null } })), expect: { valid: true } },
  {
    case: 'row 17: the mandate form with a session sign-off',
    envelope: mandated(MANDATE_FORM, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: 4 }, mandate: block() })),
    expect: { valid: false, reason: 'session_signoff_not_expected' },
  },
  { case: 'row 18: the mandate form, its block stripped', envelope: mandated(MANDATE_FORM), expect: { valid: false, reason: 'mandate_stripped' } },
  { case: 'row 19: a statement carrying signerName', envelope: mandated(MANDATE_FORM, () => ({ mandate: block({ statement: { ...W4_STATEMENT, signerName: 'Sm9zw6kgw4FsdmFyZXo' } }) })), expect: { valid: false, reason: 'malformed_mandate_statement' } },
  { case: 'row 19: a block that is not an object', envelope: mandated(MANDATE_FORM, () => ({ mandate: 'mandate' })), expect: { valid: false, reason: 'malformed_mandate_statement' } },
  {
    case: 'row 20: an assertion of another ceremony over the same challenge (another digest)',
    envelope: mandated(MANDATE_FORM, () => ({ mandate: block({ assertion: signedAssertion(W4_CHALLENGE, 'other.example') }) })),
    expect: { valid: false, reason: 'mandate_assertion_mismatch' },
  },
  {
    case: 'row 20: an ES256 assertion whose signature is not DER',
    envelope: mandated(MANDATE_FORM, () => ({ mandate: block({ assertion: { ...W4_ASSERTION, algorithm: 'ES256' } }) })),
    expect: { valid: false, reason: 'mandate_assertion_mismatch' },
  },
  {
    case: 'row 21: an assertion the record names that did not present the statement\'s challenge',
    envelope: mandated({ ...MANDATE_FORM, mandateAssertion: assertionDigestOf(elsewhere as { signature: string }) }, () => ({ mandate: block({ assertion: elsewhere }) })),
    expect: { valid: false, reason: 'mandate_unbound' },
  },
  {
    case: 'row 22: the document altered after signing',
    envelope: mandated(MANDATE_FORM, () => ({ mandate: block({ document: { ...W4_DOCUMENT, limits: { maxRecords: 20000, cumulative: null } } }) })),
    expect: { valid: false, reason: 'mandate_document_mismatch' },
  },
  {
    case: 'row 22: a statement whose signer is not the document\'s principal',
    envelope: mandated({ ...MANDATE_FORM, mandateAssertion: assertionDigestOf(foreignAssertion as { signature: string }) }, () => ({ mandate: block({ statement: foreignStatement, assertion: foreignAssertion }) })),
    expect: { valid: false, reason: 'mandate_document_mismatch' },
  },
  { case: 'row 23: confirm true, no confirmation', envelope: mandated({ ...MANDATE_FORM, confirm: true }, () => ({ mandate: block() })), expect: { valid: null, reason: 'confirmation_missing' } },
  {
    case: 'row 23: confirm true, a confirmation presenting another record\'s challenge',
    envelope: mandated({ ...MANDATE_FORM, confirm: true }, () => ({ mandate: block(), confirmation: assertionPresenting(confirmationChallengeOf(OTHER)) })),
    expect: { valid: null, reason: 'confirmation_missing' },
  },
  {
    case: 'row 24: confirm true, confirmed (the assertion presents this record\'s confirmation challenge)',
    envelope: mandated({ ...MANDATE_FORM, confirm: true }, (d) => ({ mandate: block(), confirmation: assertionPresenting(confirmationChallengeOf(d)) })),
    expect: { valid: true },
  },
  {
    case: 'a per-record signature is not a confirmation',
    envelope: mandated({ ...MANDATE_FORM, confirm: true }, (d) => ({ mandate: block(), webauthnAssertion: assertion(webauthnChallengeForDigest(d)) })),
    expect: { valid: null, reason: 'confirmation_missing' },
  },
);

/** A record exactly as a release before 0.7.0 stored it: eight hashed names, no signoffExpectation key. */
function recordFrom06(): EvidenceEnvelope {
  seq++;
  const p = {
    evidenceId: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`,
    schemaVersion: 'v1.0',
    aiSystemId: decision.aiSystemId,
    aiOutput: decision.aiOutput,
    humanAction: decision.action,
    humanReason: decision.reason,
    capturedAt: new Date(Date.parse('2026-06-26T10:00:00.000Z') + seq * 1000).toISOString(),
    sequenceNumber: 1,
    aiBom: null,
  };
  return {
    envelopeVersion: 'e1',
    payload: p,
    integrity: { canonicalDigest: computeDigest(canonicalSerialize(p, [...FIELD_SET_BEFORE_0_7])), chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  } as unknown as EvidenceEnvelope;
}
/** A record exactly as a 0.7 release stored it. */
function recordFrom07(): EvidenceEnvelope {
  const env = recordFrom06();
  const p = { ...(env.payload as unknown as Record<string, unknown>), signoffExpectation: null };
  env.payload = p as unknown as EvidenceEnvelope['payload'];
  env.integrity.canonicalDigest = computeDigest(canonicalSerialize(p, [...FIELD_SET_0_7]));
  return env;
}
const altered = recordFrom06();
(altered.payload as unknown as Record<string, unknown>).humanReason = 'rewritten';
const stripped = record(null);
delete (stripped.payload as Partial<EvidenceEnvelope['payload']>).signoffExpectation;

const predates = [
  { case: 'a record captured before 0.7.0', envelope: recordFrom06(), expect: true },
  { case: 'a record captured by a 0.7 release', envelope: recordFrom07(), expect: false },
  { case: 'a record captured by 0.8.0', envelope: record(null), expect: false },
  { case: 'a record captured by 0.8.0 whose null expectation key was stripped (its digest still holds)', envelope: stripped, expect: false },
  { case: 'a record captured before 0.7.0 and then altered', envelope: altered, expect: false },
];

/** `env` with `edit` applied after its digest was taken: its digest no longer recomputes. */
function edited(env: EvidenceEnvelope, edit: (env: EvidenceEnvelope) => void): EvidenceEnvelope {
  edit(env);
  return env;
}
const unexpect = (env: EvidenceEnvelope) => {
  env.payload.signoffExpectation = null;
};

type Verification = { case: string; envelope: EvidenceEnvelope; expect: { verified: boolean; signoffExpectation: { valid: boolean | null; reason?: string } } };
const verifications: Verification[] = [
  { case: 'intact, nothing owed', envelope: record(null), expect: { verified: true, signoffExpectation: { valid: true } } },
  {
    case: 'intact, { policyDigest } and no signature',
    envelope: record({ policyDigest: POLICY }),
    expect: { verified: true, signoffExpectation: { valid: null, reason: 'signature_missing' } },
  },
  {
    case: 'intact, a session sign-off transplanted onto a record that names no session',
    envelope: record(null, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: 4 } })),
    expect: { verified: true, signoffExpectation: { valid: false, reason: 'session_signoff_not_expected' } },
  },
  // The digest does not recompute: the expectation is not the record's own,
  // so it is not read. The check read off the rewritten value would say
  // `true` for the first two and `false` for the third.
  {
    case: 'the expectation-downgrade tamper: { policyDigest } rewritten to null, no signature carried',
    envelope: edited(record({ policyDigest: POLICY }), unexpect),
    expect: { verified: false, signoffExpectation: { valid: null, reason: 'digest_invalid' } },
  },
  {
    case: '{ policyDigest } rewritten to null, the per-record signature still carried',
    envelope: edited(record({ policyDigest: POLICY }, (d) => ({ webauthnAssertion: assertion(webauthnChallengeForDigest(d)) })), unexpect),
    expect: { verified: false, signoffExpectation: { valid: null, reason: 'digest_invalid' } },
  },
  {
    case: 'a session record whose expectation was rewritten to null, its sign-off still carried',
    envelope: edited(
      record({ statementDigest: SESSION, sessionSeq: 4 }, () => ({ webauthnAssertion: sessionAssertion(), signoff: { statement: sessionStatement, sessionSeq: 4 } })),
      unexpect,
    ),
    expect: { verified: false, signoffExpectation: { valid: null, reason: 'digest_invalid' } },
  },
  {
    case: 'another payload member edited under the digest of a { policyDigest } record',
    envelope: edited(record({ policyDigest: POLICY }), (env) => {
      env.payload.reason = 'rewritten';
    }),
    expect: { verified: false, signoffExpectation: { valid: null, reason: 'digest_invalid' } },
  },
  {
    case: 'a record captured before 0.7.0',
    envelope: recordFrom06(),
    expect: { verified: false, signoffExpectation: { valid: null, reason: 'digest_invalid' } },
  },
  {
    case: 'a record captured by a 0.7 release',
    envelope: recordFrom07(),
    expect: { verified: false, signoffExpectation: { valid: null, reason: 'digest_invalid' } },
  },
  {
    case: 'intact, the mandate form with its mandate block',
    envelope: mandated(MANDATE_FORM, () => ({ mandate: block() })),
    expect: { verified: true, signoffExpectation: { valid: true } },
  },
  {
    case: 'the mandate form rewritten to null and its block stripped, to pass the record off as a human\'s',
    envelope: edited(mandated(MANDATE_FORM), unexpect),
    expect: { verified: false, signoffExpectation: { valid: null, reason: 'digest_invalid' } },
  },
];

// A session sign-off is the signoff block alone (Record §9.3): its mode is
// session, or it carries sessionSeq. Under null and { policyDigest } that rule
// comes before any rule that reads the assertion (Verification §5, rows 2 and
// 5), so a session block reads session_signoff_not_expected with the assertion
// removed, null, or not an object. Built after every other record, so the
// records above keep their ids.
const withoutAssertion: Array<{ label: string; webauthnAssertion?: unknown }> = [
  { label: 'its assertion removed' },
  { label: 'its assertion null', webauthnAssertion: null },
  { label: 'its assertion a string', webauthnAssertion: 'assertion' },
];
for (const [expectation, block, label] of [
  [null, { statement: sessionStatement, sessionSeq: 4 }, 'null, a session block (mode session)'],
  [null, { statement: batchStatement, sessionSeq: 4 }, 'null, a block carrying sessionSeq beside a batch statement'],
  [{ policyDigest: POLICY }, { statement: sessionStatement, sessionSeq: 1 }, 'policy, a session block (mode session)'],
] as const) {
  for (const a of withoutAssertion) {
    checks.push({
      case: `${label}, ${a.label}`,
      envelope: record(expectation, () => ({ ...('webauthnAssertion' in a && { webauthnAssertion: a.webauthnAssertion }), signoff: block })),
      expect: { valid: false, reason: 'session_signoff_not_expected' },
    });
  }
}

for (const s of shapes) {
  const got = signoffExpectationViolation(s.value);
  if (got !== s.violation) throw new Error(`shapes "${s.case}": the engine says ${got}, the rule says ${s.violation}`);
}
for (const s of statementDigests) {
  const got = signoffStatementDigest(s.statement);
  if (got !== s.digest) throw new Error(`statementDigests "${s.case}": the engine says ${got}`);
  if (got !== null && signoffStatementChallenge(got) !== statementChallengeOf(got)) {
    throw new Error(`statementDigests "${s.case}": the engine's challenge differs from Record §9.4's`);
  }
}
for (const c of checks) {
  const got = checkSignoffExpectation(c.envelope);
  if (JSON.stringify(got) !== JSON.stringify(c.expect)) {
    throw new Error(`checks "${c.case}": the engine says ${JSON.stringify(got)}, the rule says ${JSON.stringify(c.expect)}`);
  }
}
for (const p of predates) {
  const got = recordPredatesSignoffExpectation(p.envelope);
  if (got !== p.expect) throw new Error(`predates "${p.case}": the engine says ${got}`);
}
for (const c of verifications) {
  const result = verifyEnvelope(c.envelope);
  const reported = {
    verified: result.verified,
    signoffExpectation: {
      valid: result.signoffExpectationValid,
      ...(result.signoffExpectationReason !== undefined && { reason: result.signoffExpectationReason }),
    },
  };
  if (JSON.stringify(reported) !== JSON.stringify(c.expect)) {
    throw new Error(`verifications "${c.case}": verifyEnvelope says ${JSON.stringify(reported)}, the rule says ${JSON.stringify(c.expect)}`);
  }
  const verdict = recordVerdict(c.envelope, { custody: { entries: [] } });
  if (JSON.stringify(verdict.signoffExpectation) !== JSON.stringify(c.expect.signoffExpectation)) {
    throw new Error(`verifications "${c.case}": recordVerdict says ${JSON.stringify(verdict.signoffExpectation)}`);
  }
}

const file = {
  description:
    'payload.signoffExpectation (Record §9, Verification §5), over records of the v1.0 hashed field set as revised in 0.8.0: its ' +
    'shape rule, the sign-off statement digest and challenge, the check a verifier makes with the expectation against the record\'s ' +
    'sign-off and mandate material (rows 1a and 17 to 24 of Verification §5 for the mandate form), the rule ' +
    'that recognises a record captured before 0.7.0, and what a verifier reports for a whole record, whose expectation it reads only ' +
    'when the digest recomputes.',
  source:
    'Computed by scripts/generate-signoff-expectation-vectors.ts. Every expected answer is written in the script from the rules, ' +
    'and the script stops if the engine disagrees with one. WebAuthn signatures here are placeholders, except the mandate statement\'s ' +
    '(the worked example W4\'s, by the RFC 8037 Appendix A key): the check reads which challenge an assertion presents, an assertion\'s ' +
    'digest, and a batch\'s inclusion proof, never whether a signature verifies.',
  shapes,
  statementDigests: statementDigests.map((d) => ({
    ...d,
    challenge: d.digest === null ? null : statementChallengeOf(d.digest),
  })),
  checks,
  predates,
  verifications,
};
process.stdout.write(JSON.stringify(file, null, 2) + '\n');
