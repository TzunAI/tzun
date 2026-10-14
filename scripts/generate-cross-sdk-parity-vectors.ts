/**
 * Generate vectors/cross-sdk-parity-vectors.json: the answers TypeScript,
 * Python and Go must agree on where their JSON readers, number types and
 * string types differ (Record §1.2, §3.1).
 *
 * Each case is a payload as JSON text (`json`), parsed by the implementation's
 * own JSON reader: the spelling of a number (`1.0`, `1e0`, `"3"`) is the
 * point. For each:
 *
 *   - `canonical` and `digest`  the bytes and the bare digest of the hashed
 *                               object (a reader hashes what is stored);
 *   - `contains`                a fragment the canonical bytes hold, the rule
 *                               the case is about (`"mandateSeq":1`);
 *   - `writer`                  what a writer's payload gate refuses
 *                               (`{ rule, code }`), or `null`;
 *   - `unhashedPayloadMembers`  the members outside the twelve names;
 *   - `rows`                    the reader's rows for the record (a genesis
 *                               envelope over the payload, no attestation):
 *                               `decider`, `contributions`, `links` (each
 *                               `{ outcome, reason? }`) and
 *                               `signoffExpectation` (`{ valid, reason? }`).
 *
 *   pnpm exec tsx scripts/generate-cross-sdk-parity-vectors.ts > vectors/cross-sdk-parity-vectors.json
 *
 * Every expected answer is written here from the specification, and the script
 * stops if the engine disagrees. The TS replay is
 * tests/cross-sdk/ts/cross-sdk-parity-vectors.test.ts; the Python
 * recomputation is tests/cross-sdk/test_cross_sdk_parity_vectors.py.
 */
import {
  canonicalSerialize,
  payloadRecordRuleViolation,
  unhashedPayloadMembers,
  verifyEnvelope,
  type EvidenceEnvelope,
} from '@tzun/engine';
import {
  AGENT,
  FIELDS,
  W4_ASSERTION_DIGEST,
  agentDecider,
  bom,
  checker,
  digestOf,
  emit,
  payload,
  prefixed,
  recordDigest,
  sha256Hex,
} from './generate-vectors-shared';

const { agree } = checker('generate-cross-sdk-parity-vectors');

/** A placeholder string a case's JSON text replaces with a raw number spelling. */
const raw = (spelling: string) => `__RAW__${spelling}__`;
const textOf = (p: Record<string, unknown>) => JSON.stringify(p).replace(/"__RAW__(.*?)__"/g, '$1');

type Row = { outcome: string; reason?: string };
type Expect = {
  contains: string;
  writer: { rule: string; code: string } | null;
  unhashedPayloadMembers: string[];
  rows: { decider: Row; contributions: Row; links: Row; signoffExpectation: { valid: boolean | null; reason?: string } };
};
const cases: Array<{ case: string; json: string } & Expect & { canonical: string; digest: string }> = [];
const correct: Row = { outcome: 'checked-correct' };
const absent: Row = { outcome: 'not-checked', reason: 'absent' };
const baseRows = { decider: correct, contributions: absent, links: absent, signoffExpectation: { valid: true } as { valid: boolean | null; reason?: string } };

function add(c: string, p: Record<string, unknown>, expect: Partial<Expect> & { contains: string }) {
  const json = textOf(p);
  const parsed = JSON.parse(json) as Record<string, unknown>;
  const canonical = canonicalSerialize(parsed, FIELDS);
  const full: Expect = {
    writer: null,
    unhashedPayloadMembers: [],
    ...expect,
    rows: { ...baseRows, ...(expect.rows ?? {}) },
  };
  cases.push({ case: c, json, canonical, digest: sha256Hex(canonical), ...full });
}

const MANDATE_LINK = [{ rel: 'mandate', target: { digest: digestOf('issuance record'), evidenceId: null, locator: null }, attrs: null }];
const mandated = (expectation: Record<string, unknown>) =>
  payload({
    decider: agentDecider('agent-mandated'),
    links: MANDATE_LINK,
    signoffExpectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 1, totals: null, confirm: false, ...expectation },
  });
const mandatedRows = { links: correct, signoffExpectation: { valid: false, reason: 'mandate_stripped' } };
const oneStep = (aiBom: unknown) => ({
  pipeline: null,
  externals: [],
  steps: [{ role: 'propose', actor: null, aiBom, inputs: [], output: prefixed({ recommendation: 'approve', score: 82 }), verdict: null, reason: null, prev: null }],
});

add('a step aiBom missing a nullable key: a writer refuses it; a reader hashes it as given', payload({ contributions: oneStep({ modelDescriptorDigest: bom().modelDescriptorDigest }) }), {
  contains: `"aiBom":{"modelDescriptorDigest":"${bom().modelDescriptorDigest}"}`,
  writer: { rule: 'contributions', code: 'invalid_step_ai_bom' },
  rows: { ...baseRows, contributions: correct },
});
add('maxTokens written 800.0: the integer 800', payload({ contributions: oneStep({ ...bom(), inferenceParameters: { temperature: raw('0.0'), topP: null, maxTokens: raw('800.0'), seed: null, stopSequences: null } }) }), {
  contains: '"inferenceParameters":{"maxTokens":800,"seed":null,"stopSequences":null,"temperature":0,"topP":null}',
  rows: { ...baseRows, contributions: correct },
});
add('mandateSeq written 1.0: the integer 1', mandated({ mandateSeq: raw('1.0') }), { contains: '"mandateSeq":1,', rows: { ...baseRows, ...mandatedRows } });
add('mandateSeq written 1e0: the integer 1', mandated({ mandateSeq: raw('1e0') }), { contains: '"mandateSeq":1,', rows: { ...baseRows, ...mandatedRows } });
add('totals written 3.0: the integer 3', mandated({ totals: { paid: raw('3.0') } }), { contains: '"totals":{"paid":3}', rows: { ...baseRows, ...mandatedRows } });
const malformedExpectation = {
  decider: { outcome: 'not-checked', reason: 'blocked_by:signoff.expectation' },
  links: correct,
  signoffExpectation: { valid: false, reason: 'malformed_signoff_expectation' },
};
add('confirm written 1 (a boolean is true or false only)', mandated({ confirm: 1 }), {
  contains: '"confirm":1,',
  writer: { rule: 'signoffExpectation', code: 'invalid_confirm' },
  rows: { ...baseRows, ...malformedExpectation },
});
add('confirm written "true"', mandated({ confirm: 'true' }), {
  contains: '"confirm":"true",',
  writer: { rule: 'signoffExpectation', code: 'invalid_confirm' },
  rows: { ...baseRows, ...malformedExpectation },
});
add('totals {"paid":"3"} (a string is never an integer)', mandated({ totals: { paid: '3' } }), {
  contains: '"totals":{"paid":"3"}',
  writer: { rule: 'signoffExpectation', code: 'invalid_totals' },
  rows: { ...baseRows, ...malformedExpectation },
});
add('mandateSeq 1.5', mandated({ mandateSeq: raw('1.5') }), {
  contains: '"mandateSeq":1.5,',
  writer: { rule: 'signoffExpectation', code: 'invalid_mandate_seq' },
  rows: { ...baseRows, ...malformedExpectation },
});
add('sequenceNumber written 1.0', payload({ sequenceNumber: raw('1.0') }), { contains: '"sequenceNumber":1,' });
add('sequenceNumber written "1": hashed as the string; a writer refuses it', payload({ sequenceNumber: '1' }), {
  contains: '"sequenceNumber":"1",',
  writer: { rule: 'payload', code: 'invalid_sequence_number' },
});
add('sequenceNumber written true', payload({ sequenceNumber: true }), {
  contains: '"sequenceNumber":true,',
  writer: { rule: 'payload', code: 'invalid_sequence_number' },
});
add('an attribute written 1.0 on an x- relation: the integer 1', payload({
  links: [{ rel: 'x-acme.renewal', target: { digest: digestOf('renewal'), evidenceId: null, locator: null }, attrs: { count: raw('1.0') } }],
}), { contains: '"attrs":{"count":1}', rows: { ...baseRows, links: correct } });
add('fanoutOf with slot written 1.0: the profile holds (slot 1); no writer in this version', payload({
  links: [{ rel: 'fanoutOf', target: { digest: digestOf('fan-out root'), evidenceId: null, locator: null }, attrs: { slot: raw('1.0'), statement: digestOf('fan-out statement') } }],
}), {
  contains: '"attrs":{"slot":1,',
  writer: { rule: 'links', code: 'relation_not_writable' },
  rows: { ...baseRows, links: correct },
});
add('an attribute value with a space (valid)', payload({
  links: [{ rel: 'x-acme.renewal', target: { digest: digestOf('renewal'), evidenceId: null, locator: null }, attrs: { region: 'eu west' } }],
}), { contains: '"attrs":{"region":"eu west"}', rows: { ...baseRows, links: correct } });
add('a target evidence id with a space (malformed)', payload({
  links: [{ rel: 'derivedFrom', target: { digest: digestOf('intake'), evidenceId: 'case 7', locator: null }, attrs: null }],
}), {
  contains: '"evidenceId":"case 7"',
  writer: { rule: 'links', code: 'invalid_target_evidence_id' },
  rows: { ...baseRows, links: { outcome: 'checked-wrong', reason: 'malformed_links' } },
});
add('a decider identifier with a trailing newline', payload({ decider: { kind: 'human', id: 'acct:u-4821\n', agent: null, credential: null, freshness: null } }), {
  contains: '"id":"acct:u-4821\\n"',
  writer: { rule: 'decider', code: 'invalid_identifier' },
  rows: { ...baseRows, decider: { outcome: 'checked-wrong', reason: 'malformed_decider' } },
});
add('a freshness reference on eip155:01', payload({
  decider: { kind: 'human', id: 'acct:u-4821', agent: null, credential: null, freshness: `eip155:01@1:0x${'ab'.repeat(32)}` },
}), {
  contains: '"freshness":"eip155:01@1:',
  writer: { rule: 'decider', code: 'invalid_freshness_reference' },
  rows: { ...baseRows, decider: { outcome: 'checked-wrong', reason: 'malformed_decider' } },
});
const withoutLegacy = payload();
add('a legacy humanAction beside the new members: not hashed, reported, refused by a writer', { ...withoutLegacy, humanAction: 'approved' }, {
  contains: '"action":"approve",',
  writer: { rule: 'payload', code: 'renamed_field' },
  unhashedPayloadMembers: ['humanAction'],
});
add('a top-level aiBom beside the new members', payload({ aiBom: bom() }), {
  contains: '"aiOutput":{',
  writer: { rule: 'payload', code: 'moved_field' },
  unhashedPayloadMembers: ['aiBom'],
});
add('a member outside the twelve names', payload({ note: 'x', Zeta: 1 }), {
  contains: '"links":null,',
  writer: { rule: 'payload', code: 'unknown_payload_member' },
  unhashedPayloadMembers: ['Zeta', 'note'],
});
add('an agent decider under jkt: the reader judges the general grammar and the kind\'s consistency', payload({
  decider: { kind: 'agent', id: 'jkt:abc', agent: AGENT, credential: null, freshness: null },
}), {
  contains: '"id":"jkt:abc"',
  writer: { rule: 'decider', code: 'invalid_identifier' },
  rows: { ...baseRows, decider: correct },
});

agree('a legacy member changes no digest', cases.find((c) => c.case.startsWith('a legacy humanAction'))!.digest, recordDigest(withoutLegacy));

const rowOf = (r: { outcome: string; reason?: string }): Row => ({ outcome: r.outcome, ...(r.reason !== undefined && { reason: r.reason }) });
for (const c of cases) {
  const parsed = JSON.parse(c.json) as Record<string, unknown>;
  if (!c.canonical.includes(c.contains)) agree(`"${c.case}" holds ${c.contains}`, c.canonical, c.contains);
  const w = payloadRecordRuleViolation(parsed);
  agree(`"${c.case}" writer`, w && { rule: w.rule, code: w.code }, c.writer);
  agree(`"${c.case}" unhashed`, unhashedPayloadMembers(parsed), c.unhashedPayloadMembers);
  const env = { envelopeVersion: 'e1', payload: parsed, integrity: { canonicalDigest: c.digest, chainLink: null }, nonRepudiation: {}, custodyChain: [], attestationStatus: 'none' } as unknown as EvidenceEnvelope;
  const v = verifyEnvelope(env);
  agree(`"${c.case}" verified`, v.verified, true);
  agree(`"${c.case}" rows`, {
    decider: rowOf(v.decider!),
    contributions: rowOf(v.contributions!),
    links: rowOf(v.links!),
    signoffExpectation: { valid: v.signoffExpectationValid, ...(v.signoffExpectationReason !== undefined && { reason: v.signoffExpectationReason }) },
  }, c.rows);
}

emit({
  description:
    'Row outcomes TypeScript, Python and Go must agree on where their JSON readers differ (Record §1.2, §3.1): number spellings that ' +
    'are integers (1.0, 1e0), values that are never integers or booleans ("3", 1, "true"), a step bill of materials missing a key, ' +
    'payload members outside the format, a trailing newline in an identifier, a space in an attribute value and in an evidence id.',
  source:
    'Generated by scripts/generate-cross-sdk-parity-vectors.ts. Every expected answer is written in the script from the specification, and the ' +
    'script stops if the engine disagrees with one. Parse `json` with the implementation\'s own JSON reader; the envelope for `rows` is ' +
    '{ payload, integrity: { canonicalDigest: digest, chainLink: null }, nonRepudiation: {} }, a genesis record.',
  cases,
});
