/**
 * Generate vectors/decider-vectors.json: the answers every implementation of
 * the decider member (Record §6) must give.
 *
 *   - shapes        a value, and why a writer refuses it as a decider
 *                   (`deciderViolation`: `{ code, field }`, or `null`). Each
 *                   case breaks one rule, so the answer does not depend on the
 *                   order the rules are tried in;
 *   - freshness     a finalized-block reference, and what it parses to
 *                   (`parseFreshnessReference`), or `null`: the three known
 *                   chains, `eip155:01`, a trailing newline, a non-ASCII digit;
 *   - consistency   kind × scheme × agent reference: the writer's refusal, in
 *                   the writer's order (agent presence, then scheme, then the
 *                   `desc` value), and whether the reader's consistency test
 *                   fails (`readerActorInconsistent`);
 *   - agreement     kind × expectation form (Record §6.5): whether they agree, what
 *                   the writer's payload gate refuses, and the reader's row;
 *   - material      a decider and the material a capture presents beside it
 *                   (Record §6.5): `kind_contradicts_material`,
 *                   `identity_contradicts_assertion`, or `null`;
 *   - rows          an envelope, and the reader's `decider` row
 *                   (`checkDecider`, Verification §4.9), every reason and fact;
 *   - commitments   `cmt` identifiers from a salt and an inner identifier, a
 *                   salt derived from a store secret and an idempotency key,
 *                   the inputs a commitment refuses, and openings.
 *
 *   pnpm exec tsx scripts/generate-decider-vectors.ts > vectors/decider-vectors.json
 *
 * Every expected answer is written here from the specification, case by case, not
 * read off the engine; the script then runs the engine over every case and
 * stops if it disagrees. The TS replay is tests/cross-sdk/ts/decider-vectors.test.ts;
 * the Python recomputation is tests/cross-sdk/test_decider_vectors.py.
 */
import { createHash, createHmac } from 'node:crypto';
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
import {
  ACCT,
  AGENT,
  AGENT_B,
  BLOCK_HASH,
  CMT,
  FRESHNESS,
  JKT,
  OTHER,
  POLICY,
  SPIFFE,
  W4_ASSERTION_DIGEST,
  agentDecider,
  assertionPresenting,
  checker,
  digestOf,
  emit,
  envelope,
  human,
  payload,
  recordAssertion,
} from './generate-vectors-shared';

const { agree } = checker('generate-decider-vectors');
const HEX = 'c4'.repeat(32);

// ── shapes ───────────────────────────────────────────────────────────────

type Shape = { case: string; value: unknown; violation: { code: string; field: string } | null };
const D = (kind: unknown, id: unknown, agent: unknown = null, credential: unknown = null, freshness: unknown = null) => ({
  kind,
  id,
  agent,
  credential,
  freshness,
});
const v = (code: string, field: string) => ({ code, field });

const shapes: Shape[] = [
  { case: 'a human under acct', value: D('human', ACCT), violation: null },
  { case: 'a human under cmt', value: D('human', CMT), violation: null },
  { case: 'an agent under desc, naming its own reference', value: D('agent', `desc:${AGENT}`, AGENT), violation: null },
  { case: 'an agent under spiffe', value: D('agent', SPIFFE, AGENT), violation: null },
  { case: 'an agent under jkt', value: D('agent', `jkt:${JKT}`, AGENT), violation: null },
  { case: 'an agent under cmt', value: D('agent', CMT, AGENT), violation: null },
  { case: 'agent-mandated under desc', value: D('agent-mandated', `desc:${AGENT}`, AGENT), violation: null },
  { case: 'a policy engine under desc', value: D('policy-engine', `desc:${AGENT}`, AGENT), violation: null },
  { case: 'a credential reference (bare 64 hex)', value: D('human', ACCT, null, HEX), violation: null },
  { case: 'freshness on Ethereum mainnet', value: D('human', ACCT, null, null, FRESHNESS), violation: null },
  { case: 'freshness on Sepolia', value: D('human', ACCT, null, null, `eip155:11155111@9123456:${BLOCK_HASH}`), violation: null },
  { case: 'freshness on Hoodi', value: D('human', ACCT, null, null, `eip155:560048@9123456:${BLOCK_HASH}`), violation: null },
  { case: 'freshness at block 0', value: D('human', ACCT, null, null, `eip155:1@0:${BLOCK_HASH}`), violation: null },
  {
    case: 'freshness at block 2^53 - 1',
    value: D('human', ACCT, null, null, `eip155:1@9007199254740991:${BLOCK_HASH}`),
    violation: null,
  },
  {
    case: 'freshness on a chain outside eip155 (the grammar admits it; the freshness row abstains)',
    value: D('human', ACCT, null, null, `bip122:000000000019d6689c085ae165831e93@840000:${BLOCK_HASH}`),
    violation: null,
  },
  { case: 'an acct value of 128 characters', value: D('human', 'acct:' + 'a'.repeat(128)), violation: null },
  { case: 'an acct value with dot, underscore and hyphen', value: D('human', 'acct:u_48.21-x'), violation: null },

  { case: 'null (every 0.8.0 writer requires a decider)', value: null, violation: v('not_an_object', 'decider') },
  { case: 'an array', value: [D('human', ACCT)], violation: v('not_an_object', 'decider') },
  { case: 'a string', value: ACCT, violation: v('not_an_object', 'decider') },
  { case: 'a member outside the five', value: { ...D('human', ACCT), note: 'x' }, violation: v('unknown_members', 'decider') },
  {
    case: 'freshness missing (a missing key is not null)',
    value: { kind: 'human', id: ACCT, agent: null, credential: null },
    violation: v('missing_members', 'decider'),
  },
  { case: 'a kind outside the four (committee)', value: D('committee', ACCT), violation: v('invalid_kind', 'decider.kind') },
  { case: 'a kind in another case (Human)', value: D('Human', ACCT), violation: v('invalid_kind', 'decider.kind') },
  { case: 'a null kind', value: D(null, ACCT), violation: v('invalid_kind', 'decider.kind') },
  { case: 'an email address under acct', value: D('human', 'acct:jane@example.com'), violation: v('invalid_identifier', 'decider.id') },
  { case: 'an acct value of 129 characters', value: D('human', 'acct:' + 'a'.repeat(129)), violation: v('invalid_identifier', 'decider.id') },
  { case: 'an uppercase scheme', value: D('human', 'ACCT:u-4821'), violation: v('invalid_identifier', 'decider.id') },
  { case: 'an identifier with a trailing newline', value: D('human', 'acct:u-4821\n'), violation: v('invalid_identifier', 'decider.id') },
  { case: 'an identifier with a space', value: D('human', 'acct:u 4821'), violation: v('invalid_identifier', 'decider.id') },
  { case: 'a non-ASCII digit in an acct value', value: D('human', 'acct:u-48٢١'), violation: v('invalid_identifier', 'decider.id') },
  { case: 'a scheme this version does not implement (did)', value: D('human', 'did:example:123'), violation: v('invalid_identifier', 'decider.id') },
  { case: 'no value after the scheme', value: D('human', 'acct:'), violation: v('invalid_identifier', 'decider.id') },
  { case: 'a number for an identifier', value: D('human', 4821), violation: v('invalid_identifier', 'decider.id') },
  {
    case: 'a spiffe path with a .. segment',
    value: D('agent', 'spiffe://claims.example/agent/../triage', AGENT),
    violation: v('invalid_identifier', 'decider.id'),
  },
  { case: 'a spiffe id with no path', value: D('agent', 'spiffe://claims.example', AGENT), violation: v('invalid_identifier', 'decider.id') },
  { case: 'a jkt value of 42 characters', value: D('agent', `jkt:${JKT.slice(1)}`, AGENT), violation: v('invalid_identifier', 'decider.id') },
  { case: 'a cmt value in uppercase hex', value: D('human', CMT.toUpperCase().replace('CMT:', 'cmt:')), violation: v('invalid_identifier', 'decider.id') },
  { case: 'a desc value that is a bare digest', value: D('agent', `desc:${AGENT.slice(7)}`, AGENT), violation: v('invalid_identifier', 'decider.id') },
  {
    case: 'an identifier of 1,025 characters',
    value: D('agent', 'spiffe://claims.example/' + 'a'.repeat(1001), AGENT),
    violation: v('invalid_identifier', 'decider.id'),
  },
  { case: 'an agent reference of 63 hex', value: D('agent', SPIFFE, AGENT.slice(0, -1)), violation: v('invalid_agent_reference', 'decider.agent') },
  { case: 'a bare agent reference', value: D('agent', SPIFFE, AGENT.slice(7)), violation: v('invalid_agent_reference', 'decider.agent') },
  { case: 'an uppercase agent reference', value: D('agent', SPIFFE, 'sha256:' + AGENT.slice(7).toUpperCase()), violation: v('invalid_agent_reference', 'decider.agent') },
  { case: 'a prefixed credential reference', value: D('human', ACCT, null, `sha256:${HEX}`), violation: v('invalid_credential_reference', 'decider.credential') },
  { case: 'a credential reference of 63 hex', value: D('human', ACCT, null, HEX.slice(1)), violation: v('invalid_credential_reference', 'decider.credential') },
  {
    case: 'eip155:01, a chain reference with a leading zero',
    value: D('human', ACCT, null, null, `eip155:01@9123456:${BLOCK_HASH}`),
    violation: v('invalid_freshness_reference', 'decider.freshness'),
  },
  {
    case: 'a block number with a leading zero',
    value: D('human', ACCT, null, null, `eip155:1@09123456:${BLOCK_HASH}`),
    violation: v('invalid_freshness_reference', 'decider.freshness'),
  },
  {
    case: 'block 2^53, past the safe integers',
    value: D('human', ACCT, null, null, `eip155:1@9007199254740992:${BLOCK_HASH}`),
    violation: v('invalid_freshness_reference', 'decider.freshness'),
  },
  {
    case: 'an uppercase block hash',
    value: D('human', ACCT, null, null, `eip155:1@9123456:0x${BLOCK_HASH.slice(2).toUpperCase()}`),
    violation: v('invalid_freshness_reference', 'decider.freshness'),
  },
  {
    case: 'a block hash without 0x',
    value: D('human', ACCT, null, null, `eip155:1@9123456:${BLOCK_HASH.slice(2)}`),
    violation: v('invalid_freshness_reference', 'decider.freshness'),
  },
  {
    case: 'a reference with a trailing newline',
    value: D('human', ACCT, null, null, `${FRESHNESS}\n`),
    violation: v('invalid_freshness_reference', 'decider.freshness'),
  },
  {
    case: 'a non-ASCII digit in the block number',
    value: D('human', ACCT, null, null, `eip155:1@912345٦:${BLOCK_HASH}`),
    violation: v('invalid_freshness_reference', 'decider.freshness'),
  },
  {
    case: 'a namespace of two characters',
    value: D('human', ACCT, null, null, `ab:1@9123456:${BLOCK_HASH}`),
    violation: v('invalid_freshness_reference', 'decider.freshness'),
  },
  { case: 'a human naming an agent reference', value: D('human', ACCT, AGENT), violation: v('agent_reference_forbidden', 'decider.agent') },
  { case: 'an agent naming none', value: D('agent', SPIFFE, null), violation: v('agent_reference_required', 'decider.agent') },
  { case: 'a policy engine naming none', value: D('policy-engine', SPIFFE, null), violation: v('agent_reference_required', 'decider.agent') },
  { case: 'a human under spiffe', value: D('human', SPIFFE), violation: v('scheme_not_permitted', 'decider.id') },
  { case: 'a human under jkt', value: D('human', `jkt:${JKT}`), violation: v('scheme_not_permitted', 'decider.id') },
  { case: 'a policy engine under acct', value: D('policy-engine', ACCT, AGENT), violation: v('scheme_not_permitted', 'decider.id') },
  { case: 'agent-mandated under acct', value: D('agent-mandated', ACCT, AGENT), violation: v('scheme_not_permitted', 'decider.id') },
  { case: 'a desc identifier naming another agent', value: D('agent', `desc:${AGENT_B}`, AGENT), violation: v('desc_identifier_mismatch', 'decider.id') },
];
for (const s of shapes) {
  const got = deciderViolation(s.value);
  agree(`shapes "${s.case}"`, got && { code: got.code, field: got.field }, s.violation);
}

// ── freshness ────────────────────────────────────────────────────────────

const parsed = (chain: string, blockNumber: number, blockHash = BLOCK_HASH) => {
  const [namespace, reference] = chain.split(':');
  return { chain, namespace, reference, blockNumber, blockHash };
};
const freshness: Array<{ case: string; reference: string; parsed: ReturnType<typeof parsed> | null }> = [
  { case: 'Ethereum mainnet', reference: FRESHNESS, parsed: parsed('eip155:1', 9123456) },
  { case: 'Sepolia', reference: `eip155:11155111@7000000:${BLOCK_HASH}`, parsed: parsed('eip155:11155111', 7000000) },
  { case: 'Hoodi', reference: `eip155:560048@1200000:${BLOCK_HASH}`, parsed: parsed('eip155:560048', 1200000) },
  { case: 'block 0', reference: `eip155:1@0:${BLOCK_HASH}`, parsed: parsed('eip155:1', 0) },
  { case: 'block 2^53 - 1', reference: `eip155:1@9007199254740991:${BLOCK_HASH}`, parsed: parsed('eip155:1', 9007199254740991) },
  {
    case: 'a chain outside eip155',
    reference: `bip122:000000000019d6689c085ae165831e93@840000:${BLOCK_HASH}`,
    parsed: parsed('bip122:000000000019d6689c085ae165831e93', 840000),
  },
  { case: 'eip155:01', reference: `eip155:01@1:${BLOCK_HASH}`, parsed: null },
  { case: 'eip155:0', reference: `eip155:0@1:${BLOCK_HASH}`, parsed: null },
  { case: 'a leading zero in the block number', reference: `eip155:1@01:${BLOCK_HASH}`, parsed: null },
  { case: 'block 2^53', reference: `eip155:1@9007199254740992:${BLOCK_HASH}`, parsed: null },
  { case: 'seventeen digits', reference: `eip155:1@10000000000000000:${BLOCK_HASH}`, parsed: null },
  { case: 'a trailing newline', reference: `${FRESHNESS}\n`, parsed: null },
  { case: 'a leading space', reference: ` ${FRESHNESS}`, parsed: null },
  { case: 'an Arabic-Indic digit', reference: `eip155:1@١:${BLOCK_HASH}`, parsed: null },
  { case: 'a fullwidth digit in the chain reference', reference: `eip155:１@1:${BLOCK_HASH}`, parsed: null },
  { case: 'an uppercase hash', reference: `eip155:1@1:0x${BLOCK_HASH.slice(2).toUpperCase()}`, parsed: null },
  { case: 'a 63-hex hash', reference: `eip155:1@1:${BLOCK_HASH.slice(0, -1)}`, parsed: null },
  { case: 'no hash', reference: 'eip155:1@1', parsed: null },
  { case: 'a chain reference of 33 characters', reference: `cosmos:${'a'.repeat(33)}@1:${BLOCK_HASH}`, parsed: null },
];
for (const f of freshness) agree(`freshness "${f.case}"`, parseFreshnessReference(f.reference), f.parsed);

// ── consistency ──────────────────────────────────────────────────────────

const KINDS: DeciderKind[] = ['human', 'agent', 'agent-mandated', 'policy-engine'];
const PERMITTED: Record<DeciderKind, string[]> = {
  human: ['acct', 'cmt'],
  agent: ['spiffe', 'jkt', 'desc', 'cmt'],
  'agent-mandated': ['spiffe', 'jkt', 'desc', 'cmt'],
  'policy-engine': ['spiffe', 'jkt', 'desc', 'cmt'],
};
const IDS: Record<string, string> = { acct: ACCT, spiffe: SPIFFE, jkt: `jkt:${JKT}`, desc: `desc:${AGENT}`, cmt: CMT };
const consistency: Array<{ case: string; kind: string; id: string; agent: string | null; writer: string | null; readerInconsistent: boolean }> = [];
for (const kind of KINDS) {
  for (const scheme of Object.keys(IDS)) {
    for (const agent of [null, AGENT]) {
      const id = IDS[scheme];
      // The writer's order: the agent reference's presence, then the scheme, then a desc value.
      let writer: string | null = null;
      if (kind === 'human' && agent !== null) writer = 'agent_reference_forbidden';
      else if (kind !== 'human' && agent === null) writer = 'agent_reference_required';
      else if (!PERMITTED[kind].includes(scheme)) writer = 'scheme_not_permitted';
      else if (scheme === 'desc' && id.slice(5) !== agent) writer = 'desc_identifier_mismatch';
      const readerInconsistent =
        (kind === 'human' ? agent !== null : agent === null) ||
        !PERMITTED[kind].includes(scheme) ||
        (scheme === 'desc' && id.slice(5) !== agent);
      consistency.push({ case: `${kind}, ${scheme}, agent ${agent === null ? 'null' : 'named'}`, kind, id, agent, writer, readerInconsistent });
    }
  }
}
// A scheme this version does not know: the reader leaves it to abstain, never calls it inconsistent.
consistency.push({ case: 'human, an unknown scheme (did), agent null', kind: 'human', id: 'did:example:123', agent: null, writer: 'invalid_identifier', readerInconsistent: false });
consistency.push({ case: 'agent, an unknown scheme (did), agent named', kind: 'agent', id: 'did:example:123', agent: AGENT, writer: 'invalid_identifier', readerInconsistent: false });
consistency.push({ case: 'agent, an unknown scheme (did), agent null', kind: 'agent', id: 'did:example:123', agent: null, writer: 'invalid_identifier', readerInconsistent: true });
for (const c of consistency) {
  const got = deciderViolation(D(c.kind, c.id, c.agent));
  agree(`consistency "${c.case}" writer`, got?.code ?? null, c.writer);
  agree(`consistency "${c.case}" reader`, readerActorInconsistent(c.kind as DeciderKind, c.id, c.agent), c.readerInconsistent);
}

// ── agreement ────────────────────────────────────────────────────────────

const mandateForm = { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 1, totals: null, confirm: false };
const FORMS: Array<[string, unknown]> = [
  ['none', null],
  ['policy', { policyDigest: POLICY }],
  ['session', { statementDigest: OTHER, sessionSeq: 3 }],
  ['mandate', mandateForm],
];
const AGREES: Record<DeciderKind, Record<string, boolean>> = {
  human: { none: true, policy: true, session: true, mandate: false },
  agent: { none: true, policy: true, session: false, mandate: false },
  'policy-engine': { none: true, policy: true, session: false, mandate: false },
  'agent-mandated': { none: false, policy: false, session: false, mandate: true },
};
const deciderFor = (kind: DeciderKind) => (kind === 'human' ? human() : agentDecider(kind));
const mandateLink = { rel: 'mandate', target: { digest: digestOf('issuance record'), evidenceId: null, locator: null }, attrs: null };
const agreement: Array<{
  case: string;
  kind: string;
  form: string;
  agrees: boolean;
  payload: Record<string, unknown>;
  writer: { rule: string; code: string } | null;
  row: Record<string, unknown>;
}> = [];
for (const kind of KINDS) {
  for (const [form, expectation] of FORMS) {
    const agrees = AGREES[kind][form];
    const p = payload({ decider: deciderFor(kind), signoffExpectation: expectation, links: form === 'mandate' ? [mandateLink] : null });
    const scheme = kind === 'human' ? 'acct' : 'desc';
    agreement.push({
      case: `${kind} under the ${form} form`,
      kind,
      form,
      agrees,
      payload: p,
      writer: agrees ? null : { rule: 'decider', code: 'kind_contradicts_expectation' },
      row: agrees
        ? { outcome: 'checked-correct', valid: true, kind, scheme, level: kind === 'human' ? 'human-asserted' : 'agent-asserted' }
        : { outcome: 'checked-wrong', valid: false, reason: 'decider_kind_contradicted', kind, scheme },
    });
  }
}
for (const a of agreement) {
  agree(`agreement "${a.case}"`, deciderAgreesWithExpectation(a.kind, a.payload.signoffExpectation), a.agrees);
  const w = payloadRecordRuleViolation(a.payload);
  agree(`agreement "${a.case}" writer`, w && { rule: w.rule, code: w.code }, a.writer);
  agree(`agreement "${a.case}" row`, checkDecider(envelope(a.payload)), a.row);
}

// ── material ─────────────────────────────────────────────────────────────

const RECORD = digestOf('the record being captured');
const material = [
  { case: 'an agent, with an assertion presenting this record\'s challenge', decider: agentDecider('agent'), material: { digest: RECORD, assertion: recordAssertion(RECORD) }, violation: v('kind_contradicts_material', 'decider.kind') },
  { case: 'agent-mandated, the same', decider: agentDecider('agent-mandated'), material: { digest: RECORD, assertion: recordAssertion(RECORD) }, violation: v('kind_contradicts_material', 'decider.kind') },
  { case: 'a policy engine, the same', decider: agentDecider('policy-engine'), material: { digest: RECORD, assertion: recordAssertion(RECORD) }, violation: v('kind_contradicts_material', 'decider.kind') },
  { case: 'an agent, with an assertion about another record', decider: agentDecider('agent'), material: { digest: RECORD, assertion: recordAssertion(OTHER) }, violation: null },
  { case: 'an agent, with an assertion presenting another challenge', decider: agentDecider('agent'), material: { digest: RECORD, assertion: assertionPresenting('AAAA') }, violation: null },
  { case: 'a human, with an assertion presenting this record\'s challenge', decider: human(), material: { digest: RECORD, assertion: recordAssertion(RECORD) }, violation: null },
  { case: 'a human under acct, the assertion\'s credential registered to that account', decider: human(), material: { assertionUserId: 'u-4821' }, violation: null },
  { case: 'a human under acct, the credential registered to another account', decider: human(), material: { assertionUserId: 'u-7702' }, violation: v('identity_contradicts_assertion', 'decider.id') },
  { case: 'a human under cmt, any account (a commitment is not compared)', decider: human(CMT), material: { assertionUserId: 'u-7702' }, violation: null },
  { case: 'a human, no assertion', decider: human(), material: {}, violation: null },
];
for (const m of material) {
  const got = deciderMaterialViolation(m.decider, m.material);
  agree(`material "${m.case}"`, got && { code: got.code, field: got.field }, m.violation);
}

// ── rows ─────────────────────────────────────────────────────────────────

const rows: Array<{ case: string; envelope: unknown; expect: Record<string, unknown> }> = [];
const row = (c: string, p: Record<string, unknown>, expect: Record<string, unknown>, nr: Parameters<typeof envelope>[1] = {}) =>
  rows.push({ case: c, envelope: envelope(p, nr), expect });
row('a decider of null', payload({ decider: null }), { outcome: 'not-checked', valid: null, reason: 'absent' });
row('no decider member (a missing top-level key reads as null)', (() => {
  const p = payload();
  delete p.decider;
  return p;
})(), { outcome: 'not-checked', valid: null, reason: 'absent' });
row('a malformed expectation blocks the row', payload({ signoffExpectation: { policyDigest: 'x' } }), {
  outcome: 'not-checked', valid: null, reason: 'blocked_by:signoff.expectation',
});
row('a member missing', payload({ decider: { kind: 'human', id: ACCT, agent: null, credential: null } }), {
  outcome: 'checked-wrong', valid: false, reason: 'malformed_decider',
});
row('a member outside the five', payload({ decider: { ...human(), note: 'x' } }), { outcome: 'checked-wrong', valid: false, reason: 'malformed_decider' });
row('eip155:01 in the freshness reference', payload({ decider: { ...human(), freshness: `eip155:01@1:${BLOCK_HASH}` } }), {
  outcome: 'checked-wrong', valid: false, reason: 'malformed_decider',
});
row('an identifier with a trailing newline', payload({ decider: human('acct:u-4821\n') }), { outcome: 'checked-wrong', valid: false, reason: 'malformed_decider' });
row('a kind that is not a string', payload({ decider: { ...human(), kind: 1 } }), { outcome: 'checked-wrong', valid: false, reason: 'malformed_decider' });
row('a kind this version does not know (committee)', payload({ decider: { kind: 'committee', id: SPIFFE, agent: AGENT, credential: null, freshness: null } }), {
  outcome: 'abstain', valid: null, reason: 'unsupported_decider_kind', kind: 'committee',
});
row('a human naming an agent reference', payload({ decider: { ...human(), agent: AGENT } }), {
  outcome: 'checked-wrong', valid: false, reason: 'decider_inconsistent', kind: 'human', scheme: 'acct',
});
row('an agent naming none', payload({ decider: { kind: 'agent', id: SPIFFE, agent: null, credential: null, freshness: null } }), {
  outcome: 'checked-wrong', valid: false, reason: 'decider_inconsistent', kind: 'agent', scheme: 'spiffe',
});
row('a human under spiffe', payload({ decider: human(SPIFFE) }), {
  outcome: 'checked-wrong', valid: false, reason: 'decider_inconsistent', kind: 'human', scheme: 'spiffe',
});
row('a desc identifier naming another agent', payload({ decider: { ...agentDecider(), id: `desc:${AGENT_B}` } }), {
  outcome: 'checked-wrong', valid: false, reason: 'decider_inconsistent', kind: 'agent', scheme: 'desc',
});
row('an agent under the session form', payload({ decider: agentDecider(), signoffExpectation: { statementDigest: OTHER, sessionSeq: 2 } }), {
  outcome: 'checked-wrong', valid: false, reason: 'decider_kind_contradicted', kind: 'agent', scheme: 'desc',
});
row('a human under a scheme this version does not know (did)', payload({ decider: human('did:example:123') }), {
  outcome: 'abstain', valid: null, reason: 'unsupported_identifier_scheme', kind: 'human', scheme: 'did',
});
row('an agent with human decision material bound (a per-record assertion over this record)', payload({ decider: agentDecider() }), {
  outcome: 'not-checked', valid: null, reason: 'material_unverified', kind: 'agent', scheme: 'desc', kindContradiction: 'undetermined',
}, (d) => ({ webauthnAssertion: recordAssertion(d) }));
row('an agent with an assertion about another record (not bound)', payload({ decider: agentDecider() }), {
  outcome: 'checked-correct', valid: true, kind: 'agent', scheme: 'desc', level: 'agent-asserted',
}, { webauthnAssertion: recordAssertion(OTHER) });
row('a human under acct', payload(), { outcome: 'checked-correct', valid: true, kind: 'human', scheme: 'acct', level: 'human-asserted' });
row('a human under acct with a per-record assertion bound', payload(), {
  outcome: 'checked-correct', valid: true, kind: 'human', scheme: 'acct', level: 'human-asserted', levelUndetermined: 'human-proven',
}, (d) => ({ webauthnAssertion: recordAssertion(d) }));
row('a human under cmt', payload({ decider: human(CMT) }), {
  outcome: 'checked-correct', valid: true, kind: 'human', scheme: 'cmt', level: 'human-asserted', committed: true,
});
row('an email address under acct: a writer refuses it, a reader applies only the general grammar', payload({ decider: human('acct:jane@example.com') }), {
  outcome: 'checked-correct', valid: true, kind: 'human', scheme: 'acct', level: 'human-asserted',
});
row('a policy engine', payload({ decider: agentDecider('policy-engine') }), {
  outcome: 'checked-correct', valid: true, kind: 'policy-engine', scheme: 'desc', level: 'agent-asserted',
});
row('agent-mandated under the mandate form', payload({ decider: agentDecider('agent-mandated'), signoffExpectation: mandateForm, links: [mandateLink] }), {
  outcome: 'checked-correct', valid: true, kind: 'agent-mandated', scheme: 'desc', level: 'agent-asserted',
});
for (const r of rows) agree(`rows "${r.case}"`, checkDecider(r.envelope), r.expect);

// ── commitments ──────────────────────────────────────────────────────────

const commitmentOf = (innerId: string, salt: Buffer) =>
  'cmt:' + createHash('sha256').update('tzun-decider-cmt-v1', 'utf8').update(salt).update(innerId, 'utf8').digest('hex');
const commitmentCases: Array<[string, string, Buffer]> = [
  ['the example commitment (salt 0x00..0x1f)', ACCT, Buffer.from(Array.from({ length: 32 }, (_, i) => i))],
  ['salt 0xff × 32', ACCT, Buffer.alloc(32, 0xff)],
  ['a spiffe identifier', SPIFFE, createHash('sha256').update('salt one').digest()],
  ['a desc identifier', `desc:${AGENT}`, createHash('sha256').update('salt two').digest()],
];
const commitments = commitmentCases.map(([label, innerId, salt]) => {
  const commitment = commitmentOf(innerId, salt);
  agree(`commitment "${label}"`, deciderCommitment(innerId, salt), commitment);
  agree(`commitment "${label}" from base64url`, deciderCommitment(innerId, salt.toString('base64url')), commitment);
  return { case: label, innerId, saltHex: salt.toString('hex'), saltBase64url: salt.toString('base64url'), commitment };
});
agree('the example commitment', commitments[0].commitment, CMT);

const lengthPrefixed = (text: string) => {
  const bytes = Buffer.from(text, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(bytes.length);
  return Buffer.concat([len, bytes]);
};
const secret = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i));
const derivedSalts = [
  ['capture-7', ACCT],
  ['capture-7', SPIFFE],
  ['a key with UTF-8 é', ACCT],
].map(([idempotencyKey, innerId]) => {
  const salt = createHmac('sha256', secret).update('tzun-cmt-salt-v1', 'utf8').update(lengthPrefixed(idempotencyKey)).update(lengthPrefixed(innerId)).digest();
  agree(`derived salt ${idempotencyKey} ${innerId}`, deciderCommitmentSalt(secret, idempotencyKey, innerId), salt.toString('base64url'));
  return { secretHex: secret.toString('hex'), idempotencyKey, innerId, saltBase64url: salt.toString('base64url'), commitment: commitmentOf(innerId, salt) };
});

const refusals: Array<{ case: string; innerId: string; saltHex: string; refused: true }> = [
  { case: 'a salt of 31 bytes', innerId: ACCT, saltHex: '00'.repeat(31), refused: true },
  { case: 'a salt of 33 bytes', innerId: ACCT, saltHex: '00'.repeat(33), refused: true },
  { case: 'an inner identifier under cmt', innerId: CMT, saltHex: '00'.repeat(32), refused: true },
  { case: 'an inner identifier under a scheme this version does not know', innerId: 'did:example:123', saltHex: '00'.repeat(32), refused: true },
  { case: 'an inner acct value with @', innerId: 'acct:jane@example.com', saltHex: '00'.repeat(32), refused: true },
];
for (const r of refusals) {
  let threw = false;
  try {
    deciderCommitment(r.innerId, Buffer.from(r.saltHex, 'hex'));
  } catch {
    threw = true;
  }
  agree(`commitment refusal "${r.case}"`, threw, true);
}

const exampleSalt = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('base64url');
const openings = [
  { case: 'the example opening', id: CMT, opening: { salt: exampleSalt, id: ACCT }, opens: true },
  { case: 'another inner identifier', id: CMT, opening: { salt: exampleSalt, id: 'acct:u-4822' }, opens: false },
  { case: 'another salt', id: CMT, opening: { salt: Buffer.alloc(32, 0xff).toString('base64url'), id: ACCT }, opens: false },
  { case: 'the salt padded with =', id: CMT, opening: { salt: exampleSalt + '=', id: ACCT }, opens: false },
  { case: 'the salt in standard base64', id: CMT, opening: { salt: Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('base64'), id: ACCT }, opens: false },
  { case: 'an identifier that is not a commitment', id: ACCT, opening: { salt: exampleSalt, id: ACCT }, opens: false },
  { case: 'no salt', id: CMT, opening: { id: ACCT }, opens: false },
];
for (const o of openings) agree(`opening "${o.case}"`, verifyDeciderOpening(o.id, o.opening), o.opens);

emit({
  description:
    'The decider member of a v1.0 record (Record §6): the writer\'s refusals, finalized-block references, the consistency of kind, ' +
    'scheme and agent reference, agreement with the signature expectation, the material a capture presents, the reader\'s decider row ' +
    '(Verification §4.9), and identifier commitments.',
  source:
    'Generated by scripts/generate-decider-vectors.ts. Every expected answer is written in the script from the specification, and the ' +
    'script stops if the engine disagrees with one. A writer tries its rules in this order: shape (not_an_object, unknown_members, ' +
    'missing_members), kind, identifier, agent reference, credential reference, freshness reference, agent presence ' +
    '(agent_reference_forbidden, agent_reference_required), scheme, desc value. Each shapes case breaks one rule; the consistency grid ' +
    'breaks several and pins the order. WebAuthn signatures here are placeholders: the checks read which challenge an assertion presents.',
  shapes,
  freshness,
  consistency,
  agreement,
  material,
  rows,
  commitments,
  derivedSalts,
  commitmentRefusals: refusals,
  openings,
});
