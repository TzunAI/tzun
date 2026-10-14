/**
 * Generate vectors/v1.0-canonical-vectors.json: canonical serialization of
 * the v1.0 record as revised in place in 0.8.0 (Record §3, §4.1). The case
 * ids V01 to V27 keep their subjects; their inputs carry the eleven hashed
 * names (`action` and `reason` for `humanAction` and `humanReason`, and
 * `decider`, `contributions` and `links`). V28 was withdrawn. V29 to V38 and
 * N04 are new.
 *
 *   V01–V16, V22, V24, V25  the serializer's rules, exercised in `aiOutput`
 *                           and `reason`: key order, nesting, null, arrays,
 *                           numbers, booleans, escaping, Unicode, undefined;
 *   V17–V19                 no model, a minimal and a fully populated step
 *                           bill of materials (a contributions list of one);
 *   V20, V21, V23           model descriptors (the set sub-rule; unchanged);
 *   V26, V27                the policy and session forms of the expectation;
 *   V29–V38                 a human decider under cmt; a policy engine; W3;
 *                           one digest under two relations; the mandate form
 *                           with totals; every new member null; Unicode in
 *                           reason and in a step reason; a step with every
 *                           member populated; a salted step output; an x-
 *                           extension link with attributes;
 *   N01–N04                 input the serializer refuses: a lone surrogate, NaN,
 *                           nesting past the limit, a lone surrogate in a step
 *                           reason.
 *
 * Every envelope input holds exactly the eleven hashed names, so serializing
 * the whole input and serializing it under the v1.0 hashed field set give the
 * same bytes (the TypeScript suite does the one, the Python suite the other).
 *
 *   pnpm exec tsx scripts/generate-v1.0-canonical-vectors.ts > vectors/v1.0-canonical-vectors.json
 *
 * The script stops if the bytes of a whole input and of its hashed fields
 * differ, if an input holds a name outside the eleven, if W3's bytes are not
 * the worked example's, or if the serializer accepts a negative vector.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalSerialize, canonicalSerializeDescriptor, canonicalSerializeValue, type ModelDescriptor } from '@tzun/engine';
import {
  AGENT,
  CMT,
  FIELDS,
  LENDER_ORIGIN,
  MODEL,
  RawJson,
  W4_ASSERTION_DIGEST,
  bom,
  checker,
  digestOf,
  emit,
  prefixed,
} from './generate-vectors-shared';

const { agree, stop } = checker('generate-v1.0-canonical-vectors');

const DECIDER = { kind: 'human', id: 'acct:u-1', agent: null, credential: null, freshness: null };
/** The members V01–V16, V22, V24 and V25 share: their subject is in `aiOutput`, `action` or `reason`. */
const base = {
  evidenceId: 'abc',
  aiSystemId: 'sys1',
  aiOutput: { r: 'approve' } as unknown,
  action: 'approved',
  reason: 'ok',
  capturedAt: '2026-01-01T00:00:00Z',
  sequenceNumber: 1,
  decider: DECIDER as unknown,
  contributions: null as unknown,
  links: null as unknown,
  signoffExpectation: null as unknown,
};
type Input = typeof base;
const env = (edit: Partial<Input>): Input => ({ ...base, ...edit });

const UNDEFINED = 'UNDEFINED_MARKER';
/** The input as a harness hands it to the serializer: UNDEFINED_MARKER becomes undefined. */
function materialize(value: unknown): unknown {
  if (value === UNDEFINED) return undefined;
  if (value instanceof RawJson) return value.value;
  if (Array.isArray(value)) return value.map(materialize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, materialize(v)]));
  }
  return value;
}

type Vector = { id: string; kind: 'envelope-v1.0' | 'descriptor'; description: string; note?: string; input: unknown; canonical: string };
const vectors: Vector[] = [];
function envelopeCase(id: string, description: string, input: Input, note?: string) {
  const keys = Object.keys(input).sort();
  agree(`${id} members`, keys, [...FIELDS].sort());
  const value = materialize(input) as Record<string, unknown>;
  const canonical = canonicalSerialize(value, FIELDS);
  if (canonicalSerializeValue(value) !== canonical) stop(`${id}: the whole input and its hashed fields serialize differently`);
  vectors.push({ id, kind: 'envelope-v1.0', description, ...(note !== undefined && { note }), input, canonical });
}
function descriptorCase(id: string, description: string, input: ModelDescriptor, note?: string) {
  vectors.push({ id, kind: 'descriptor', description, ...(note !== undefined && { note }), input, canonical: canonicalSerializeDescriptor(input) });
}

// ── V01–V16: the serializer's rules ─────────────────────────────────────

envelopeCase('V01', 'Simple flat object — keys reordered alphabetically', env({}));
envelopeCase('V02', 'Nested object with unsorted keys — recursive sort', env({ aiOutput: { z: 1, a: 2, m: { zz: true, aa: false } } }));
envelopeCase('V03', 'Null value preserved', env({ aiOutput: { score: null, label: 'good' } }));
envelopeCase('V04', 'Array preserves insertion order', env({ aiOutput: { items: ['c', 'a', 'b'] } }));
envelopeCase('V05', 'Empty object', env({ aiOutput: {} }));
envelopeCase('V06', 'Numeric types — integer, decimal, large integer', env({ aiOutput: { count: 1, ratio: 0.5, big: 1000000 } }));
envelopeCase('V07', 'Boolean values', env({ aiOutput: { flagged: true, override: false } }));
envelopeCase('V08', 'Deeply nested — 3 levels', env({ aiOutput: { l1: { l2: { l3: 'deep' } } } }));
envelopeCase('V09', 'Special characters in strings — quotes and ampersand', env({ reason: 'User said "yes" & confirmed' }));
envelopeCase('V10', 'Unicode passthrough — no normalization', env({ reason: 'Approved — résumé reviewed' }));
envelopeCase(
  'V11',
  'Undefined converted to null',
  env({ aiOutput: { score: UNDEFINED, label: 'good' } }),
  'In TypeScript tests, pass undefined for aiOutput.score. In JSON, UNDEFINED_MARKER signals this. The canonical output must serialize undefined as null.',
);
envelopeCase('V12', 'Array of objects — objects in arrays get key-sorted too', env({ aiOutput: { items: [{ z: 1, a: 2 }, { b: 3, c: 4 }] } }));
envelopeCase('V13', 'Control characters in string — tab and newline', env({ reason: 'line1\nline2\ttab' }));
envelopeCase('V14', 'Empty string values', env({ aiOutput: { r: '' }, action: '', reason: '' }), 'A writer refuses an empty action or reason; the serializer renders them.');
envelopeCase('V15', 'Numeric edge cases — zero, negative, small decimal', env({ aiOutput: { zero: 0, neg: -1, small: 0.001 } }));
envelopeCase(
  'V16',
  'Unicode supplementary characters (emoji) in keys and values — verifies Unicode code point sort order',
  env({ aiOutput: { '\u{1F512}': 'locked', a: 'first', '\u{1F4CA}': 'chart' } }),
  "JavaScript's default .sort() uses UTF-16 code unit comparison. For supplementary characters (emoji), this produces the same order as " +
    "Unicode code point order within the BMP and supplementary planes separately. Keys sort as: 'a' (U+0061), '\u{1F4CA}' (U+1F4CA), " +
    "'\u{1F512}' (U+1F512) — ASCII before supplementary, then supplementary by code point.",
);

// ── V17–V19: the bill of materials in a step ────────────────────────────

const oneStep = (aiBom: unknown) => ({
  pipeline: null,
  externals: [],
  steps: [{ role: 'propose', actor: null, aiBom, inputs: [], output: prefixed({ r: 'approve' }), verdict: null, reason: null, prev: null }],
});
envelopeCase('V17', 'contributions null: the record names no model', env({ aiOutput: { recommendation: 'approve', score: 0.82 }, reason: 'A rule decided; no model was called' }));
envelopeCase(
  'V18',
  'A list of one with a minimal step aiBom — only modelDescriptorDigest populated; siblings explicit null',
  env({ contributions: oneStep(bom('sha256:' + 'ab'.repeat(32))) }),
);
envelopeCase(
  'V19',
  'A list of one with a fully populated step aiBom — every sub-object, stopSequences in insertion order',
  env({
    contributions: oneStep({
      modelDescriptorDigest: 'sha256:' + 'ab'.repeat(32),
      vendorFingerprint: 'fp-001',
      promptTemplate: { templateId: 'tpl-1', templateDigest: 'sha256:tpl' },
      inferenceParameters: { temperature: 0.7, topP: 0.9, maxTokens: 1024, seed: 42, stopSequences: ['END', 'STOP'] },
      infrastructure: { provider: 'openai', region: 'us-east-1', apiVersion: '2024-10-01', endpoint: 'https://api.openai.com' },
    }),
  }),
  'stopSequences preserves insertion order under the base array rule (the descriptor sub-rule does not apply inside a step aiBom).',
);

// ── V20, V21, V23: model descriptors ────────────────────────────────────

descriptorCase('V20', 'ModelDescriptor canonical bytes — empty set-valued fields (the set sub-rule is a no-op)', {
  descriptorVersion: 'd1', vendor: 'openai', modelName: 'gpt-4o', modelVersion: '2024-08-06', modelType: null, integrityTier: 'vendor-asserted',
  modelDigest: null, parentModelDescriptorDigest: null, derivation: null, trainedBy: null, license: null, modelCardUrl: null,
  training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
  regulatoryMarkings: [], externalIdentifiers: [],
}, 'Exercises canonicalSerializeDescriptor with empty regulatoryMarkings / training.evaluations / externalIdentifiers — the descriptor sub-rule must be a no-op here.');
descriptorCase('V21', 'ModelDescriptor canonical bytes — populated set-valued fields, supplied unsorted (the set sub-rule sorts each one)', {
  descriptorVersion: 'd1', vendor: 'openai', modelName: 'gpt-4o', modelVersion: '2024-08-06', modelType: 'chat', integrityTier: 'vendor-asserted',
  modelDigest: null, parentModelDescriptorDigest: null, derivation: 'base', trainedBy: null, license: 'proprietary', modelCardUrl: null,
  training: {
    trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null,
    evaluations: [
      { name: 'mmlu', testSetDigest: null, evaluatedAt: null, metrics: { accuracy: 0.88 } },
      { name: 'arc-challenge', testSetDigest: null, evaluatedAt: null, metrics: {} },
    ],
  },
  regulatoryMarkings: [
    { authority: 'us-fda', identifier: 'K2', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
    { authority: 'eu-ce-mdr', identifier: 'CE1', status: 'active', effectiveDate: null, expiresAt: null, scope: null, evidenceUrl: null },
  ],
  externalIdentifiers: [
    { scheme: 'hf-repo', value: 'meta-llama/x', issuedBy: null, issuedAt: null, url: null },
    { scheme: 'doi', value: '10.0/y', issuedBy: null, issuedAt: null, url: null },
  ],
} as unknown as ModelDescriptor, 'Input arrays are deliberately out of order: regulatoryMarkings by (authority,identifier) sorts (eu-ce-mdr,CE1) before (us-fda,K2); training.evaluations by name sorts arc-challenge before mmlu; externalIdentifiers by (scheme,value) sorts (doi,10.0/y) before (hf-repo,meta-llama/x).');

// ── V22, V24, V25 ───────────────────────────────────────────────────────

envelopeCase(
  'V22',
  'Number rendering follows JS Number::toString — 1e-6/1e21 thresholds, unpadded exponent, >17-significant-digit integer-valued floats',
  env({
    aiOutput: new RawJson(
      '{"expNegFive": 1e-05, "expNegSix": 1e-06, "expNegSeven": 1e-07, "exp21": 1e+21, "exp20": 1e+20, "maxDouble": 1.7976931348623157e+308, ' +
        '"minSubnormal": 5e-324, "wideInteger": 1.2345678901234568e+20, "addFloat": 0.30000000000000004, "maxSafeInteger": 9007199254740991, ' +
        '"minSafeInteger": -9007199254740991}',
    ),
  }),
  'Every literal is written with an exponent or a decimal point on purpose: without one it parses back as a Python int, and integers outside ' +
    '+/-(2^53-1) are refused rather than rendered differently in the two SDKs. Negative zero is covered by a unit test instead — JSON cannot carry it.',
);
descriptorCase('V23', 'ModelDescriptor set-valued sub-rule sorts by UTF-16 code unit, not Unicode code point', {
  descriptorVersion: 'd1', vendor: 'acme', modelName: 'm', modelVersion: '1', modelType: null, integrityTier: 'vendor-asserted',
  modelDigest: null, parentModelDescriptorDigest: null, derivation: null, trainedBy: null, license: null, modelCardUrl: null,
  training: {
    trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null,
    evaluations: [{ name: 'Ａeval', metric: 'm', value: 1 }, { name: '\u{1F600}eval', metric: 'm', value: 2 }],
  },
  regulatoryMarkings: [{ authority: 'ＡEU', identifier: 'x' }, { authority: '\u{1F600}EU', identifier: 'y' }],
  externalIdentifiers: [{ scheme: 'Ａsbom', value: 'a' }, { scheme: '\u{1F600}sbom', value: 'b' }],
} as unknown as ModelDescriptor, "U+1F600 is supplementary-plane: its first UTF-16 code unit is 0xD83D, BELOW U+FF21 (0xFF21). Python's default string sort compares code points and orders these the other way round, so this vector discriminates the two orders.");
envelopeCase(
  'V24',
  'Object key order discriminates UTF-16 code-unit sort from Unicode code-point sort',
  env({ aiOutput: { '！': 1, '\u{1F600}': 2, a: 3 } }),
  "V16's three keys sort identically under both orderings, which its own note admits, so it cannot catch a sort regression. This one can: " +
    'U+FF01 is a BMP key whose single code unit is 0xFF01; U+1F600 is astral and its FIRST code unit is 0xD83D. UTF-16 order puts the emoji ' +
    'first; code-point order puts U+FF01 first. Any switch to code-point key ordering in either SDK changes these bytes.',
);
envelopeCase('V25', 'Object key containing a quote and a colon is escaped, not structural', env({ aiOutput: { 'a"b:c': 1, a: 2 } }));

// ── V26, V27: the expectation ───────────────────────────────────────────

envelopeCase('V26', 'signoffExpectation { policyDigest } is hashed as a nested object', env({
  signoffExpectation: { policyDigest: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4' },
}));
envelopeCase('V27', 'signoffExpectation { statementDigest, sessionSeq } is hashed with its members sorted', env({
  signoffExpectation: { sessionSeq: 12, statementDigest: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae' },
}), 'sessionSeq is supplied before statementDigest; the canonical form sorts them.');

// ── V29–V38: the new members ────────────────────────────────────────────

envelopeCase('V29', 'A human decider under a commitment (cmt)', env({ decider: { ...DECIDER, id: CMT } }));
envelopeCase('V30', 'A policy-engine decider, named by its agent descriptor', env({
  decider: { kind: 'policy-engine', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null },
}));
const worked = JSON.parse(readFileSync(join(__dirname, '..', 'vectors', 'v1.0-worked-example-vectors.json'), 'utf8')) as {
  records: Array<{ id: string; payload: Record<string, unknown>; canonical: string }>;
};
const w3 = worked.records.find((r) => r.id === 'W3')!;
const { schemaVersion: _sv, ...w3Hashed } = w3.payload;
envelopeCase('V31', 'The worked example W3: two models, a human decide step, derivedFrom and root links, the policy form', w3Hashed as unknown as Input,
  'Its bytes are W3\'s in v1.0-worked-example-vectors.json; schemaVersion, which is not hashed, is left out of the input.');
agree('V31 is W3', vectors[vectors.length - 1].canonical, w3.canonical);
const TARGET = digestOf('V32 target');
envelopeCase('V32', 'One target digest under two relations (derivedFrom and root): links sorted by (rel, target.digest)', env({
  links: [
    { rel: 'derivedFrom', target: { digest: TARGET, evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000006', locator: { origin: LENDER_ORIGIN, seq: 6 } }, attrs: null },
    { rel: 'root', target: { digest: TARGET, evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000006', locator: { seq: 6, origin: LENDER_ORIGIN } }, attrs: null },
  ],
}), 'The root link\'s locator members are supplied seq first; the canonical form sorts them.');
envelopeCase('V33', 'The mandate form of the expectation with totals, members supplied unsorted', env({
  decider: { kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null },
  signoffExpectation: { totals: { refunds: 0, paid: 5230000 }, mandateSeq: 41, confirm: false, mandateAssertion: W4_ASSERTION_DIGEST },
  links: [{ rel: 'mandate', target: { digest: 'fb29b130c25c42d6ac72f1ea4123f0c542d6fefed9cfcaaa6b9a1b5e74af9844', evidenceId: null, locator: null }, attrs: null }],
}));
envelopeCase('V34', 'Every new member null (a reader reads decider null as not recorded)', env({ decider: null }));
envelopeCase('V35', 'Unicode in reason and in a step reason, not normalised (precomposed and decomposed é, an astral character)', env({
  reason: 'Revu par l’équipe — café vs café \u{1F9FE}',
  contributions: {
    pipeline: null,
    externals: [],
    steps: [{ role: 'decide', actor: { kind: 'human', id: 'acct:u-1', agent: null }, aiBom: null, inputs: [], output: prefixed({ action: 'approved', reason: 'x' }), verdict: 'approve', reason: 'Étape décidée \u{1F9FE}', prev: null }],
  },
}));
envelopeCase('V36', 'A step with every member populated: actor, a fully populated aiBom, inputs, verdict, reason and prev', env({
  contributions: {
    pipeline: prefixed('a pipeline definition'),
    externals: [prefixed('the request')],
    steps: [
      { role: 'propose', actor: null, aiBom: bom(MODEL), inputs: [prefixed('the request')], output: prefixed({ r: 'approve' }), verdict: null, reason: null, prev: null },
      {
        role: 'review:compliance',
        actor: { kind: 'agent', id: `desc:${AGENT}`, agent: AGENT },
        aiBom: {
          modelDescriptorDigest: MODEL,
          vendorFingerprint: 'fp_44709d6fcb',
          promptTemplate: { templateId: 'review-v3', templateDigest: prefixed('review prompt v3') },
          inferenceParameters: { temperature: 0, topP: 1, maxTokens: 800, seed: 7, stopSequences: ['</review>'] },
          infrastructure: { provider: 'azure-openai', region: 'westeurope', apiVersion: '2024-10-21', endpoint: 'https://example.openai.azure.com' },
        },
        inputs: [prefixed({ r: 'approve' })],
        output: prefixed({ verdict: 'concerns' }),
        verdict: 'concerns',
        reason: 'Income evidence is older than 90 days',
        prev: prefixed('the step before, as the builder chains it'),
      },
    ],
  },
}), 'prev is a well-formed digest, not the computed one: this vector is about bytes, and a reader reports the broken chain.');
const SALT = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex').toString('base64url');
envelopeCase('V37', 'A salted step output (Record §7.6): the output digest of { salt, value }', env({
  contributions: { pipeline: null, externals: [], steps: [{ ...oneStep(bom()).steps[0], output: prefixed({ salt: SALT, value: { verdict: 'approve' } }) }] },
}), `The step output is outputDigest({ "salt": "${SALT}", "value": { "verdict": "approve" } }); the salt travels outside the record.`);
envelopeCase('V38', 'An x- extension link with attributes (a string with a space, an integer, a boolean), supplied unsorted', env({
  links: [{ rel: 'x-acme.contractRenewal', target: { digest: digestOf('V38 target'), evidenceId: 'C-1182', locator: null }, attrs: { renewals: 3, region: 'eu west', final: true } }],
}));

// ── negatives ────────────────────────────────────────────────────────────

const negativeVectors = [
  { id: 'N01', description: 'Lone UTF-16 surrogate in a string value is refused, not silently mangled', expectError: 'lone surrogate',
    note: 'The sentinel LONE_SURROGATE_D800 stands in for a real unpaired U+D800; JSON text cannot carry one, so each harness substitutes it before serializing.',
    input: env({ aiOutput: { s: 'a LONE_SURROGATE_D800 b' } }) },
  { id: 'N02', description: 'NaN is refused — non-finite numbers have no canonical rendering', expectError: 'non-finite',
    note: 'The sentinel NAN_MARKER stands in for NaN, which JSON cannot carry.', input: env({ aiOutput: { n: 'NAN_MARKER' } }) },
  { id: 'N03', description: 'Nesting past MAX_DEPTH is refused rather than truncated or looped', expectError: 'nesting depth',
    input: env({ aiOutput: Array.from({ length: 70 }).reduce<unknown>((inner) => ({ n: inner }), 'deep') }) },
  { id: 'N04', description: 'A lone UTF-16 surrogate in a contribution step reason is refused', expectError: 'lone surrogate',
    note: 'The sentinel LONE_SURROGATE_D800 stands in for a real unpaired U+D800 inside contributions.steps[0].reason.',
    input: env({ contributions: { ...oneStep(bom()), steps: [{ ...oneStep(bom()).steps[0], role: 'other', reason: 'see LONE_SURROGATE_D800 here' }] } }) },
];
const sentinels = (value: unknown): unknown => {
  if (typeof value === 'string') return value === 'NAN_MARKER' ? NaN : value.replace(/LONE_SURROGATE_D800/g, '\uD800');
  if (Array.isArray(value)) return value.map(sentinels);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, sentinels(v)]));
  return value;
};
for (const n of negativeVectors) {
  for (const serialize of [() => canonicalSerialize(sentinels(n.input) as Record<string, unknown>, FIELDS), () => canonicalSerializeValue(sentinels(n.input))]) {
    let message = '';
    try {
      serialize();
    } catch (e) {
      message = (e as Error).message;
    }
    if (!new RegExp(n.expectError, 'i').test(message)) stop(`${n.id}: the serializer did not refuse it with "${n.expectError}" (${message || 'no error'})`);
  }
}

emit({
  schemaVersion: 'v1.0',
  description:
    'Cross-language conformance test vectors for canonical serialization v1.0 (Record §3), under the hashed field set as revised in ' +
    '0.8.0 (Record §4.1). Each envelope-v1.0 input holds exactly the eleven hashed names, so the whole input and its hashed fields ' +
    'serialize to the same bytes. Entries under `negativeVectors` MUST raise in every SDK; a canonicalizer that returns bytes for any of them is broken.',
  source: 'Generated by scripts/generate-v1.0-canonical-vectors.ts.',
  vectors,
  negativeVectors,
});
