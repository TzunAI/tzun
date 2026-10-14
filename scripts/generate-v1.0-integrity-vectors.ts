/**
 * Generate vectors/v1.0-integrity-vectors.json: the digest form, the chain
 * link, and digests over whole v1.0 payloads as revised in place in 0.8.0
 * (Record §4, §5).
 *
 *   I01      a literal vector: the digest form only;
 *   I02–I03  the chain link;
 *   I04      an object input that loads every rule the digest depends on;
 *   I05      a whole 0.8.0 payload under the session form, members unsorted,
 *            `schemaVersion` present and not hashed;
 *   I06–I07  a payload that omits the members that are null, and the same
 *            payload with them written: one digest (a missing top-level key
 *            and a null one serialize alike, Record §4.2);
 *   I08      a payload as a 0.7 release stored it, hashed under the eleven
 *            names: `humanAction`, `humanReason` and `aiBom` are not hashed,
 *            and `action` and `reason` serialize as null, so its digest is
 *            not the one such a record carries. That is why a 0.8.0 reader
 *            reports a 0.7 record `digest_mismatch`.
 *
 *   pnpm exec tsx scripts/generate-v1.0-integrity-vectors.ts > vectors/v1.0-integrity-vectors.json
 *
 * The script computes every canonical string and digest with the engine's
 * serializer and node:crypto, and stops if I06 and I07 differ, if I08's digest
 * is the one its 0.7 field set gives, or if I04 changed from the corpus it
 * replaces.
 */
import { createHash } from 'node:crypto';
import { EvidenceChain, FIELD_SET_0_7, canonicalSerialize } from '@tzun/engine';
import { FIELDS, checker, emit, human } from './generate-vectors-shared';

const { stop } = checker('generate-v1.0-integrity-vectors');
const sha256Hex = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

function objectInput(id: string, note: string, input: Record<string, unknown>, hashedFields: string[]) {
  const expectedCanonical = canonicalSerialize(input, hashedFields);
  return { id, kind: 'digest', note, input, hashedFields, expectedCanonical, expectedDigest: sha256Hex(expectedCanonical) };
}

const I04 = objectInput(
  'I04',
  'Object-input vector. Both SDKs run their OWN canonicalizer over `input` under `hashedFields` and must reproduce ' +
    '`expectedCanonical` byte-for-byte before hashing, so a canonicalizer divergence fails HERE and not only in the canonical corpus. It ' +
    'deliberately loads every rule the integrity digest depends on: hashed-field selection and re-sort (`hashedFields` is supplied unsorted ' +
    'and names `missing_from_input`, absent from `input`, which must serialize as null); an explicit null that must survive as null; string ' +
    'escaping for quote, newline, tab and a U+0001 control char; non-ASCII passthrough (U+00E9) with no \\u escaping; UTF-16 key ordering ' +
    'across a BMP fullwidth key (U+FF01) and an astral key (U+1F600); exponent-form numbers at both ends (1e-7, 1e+21); and MAX_SAFE_INTEGER ' +
    'rendered without an exponent.',
  {
    zeta: 1e-7,
    alpha: 'café "quoted"\n\t\u0001 end',
    middle: { b: [1, null, true, 1e21], a: 9007199254740991 },
    '！': 1,
    '\u{1F600}': 2,
    explicit_null: null,
  },
  ['explicit_null', 'alpha', 'middle', 'missing_from_input', 'zeta', '！', '\u{1F600}'],
);
if (I04.expectedDigest !== '64c65547f68844b0e84a52c2edc6bbc5ccaf2cb35098acde0d0106e6abae86cf') stop('I04 changed');

const I05 = objectInput(
  'I05',
  'Object-input vector over a whole v1.0 payload, as revised in 0.8.0, whose signoffExpectation is the session form. `hashedFields` is ' +
    'the v1.0 hashed field set: `schemaVersion` is in `input` and not hashed, and the members of signoffExpectation and of the decider are ' +
    'supplied out of order and must be sorted.',
  {
    schemaVersion: 'v1.0',
    sequenceNumber: 3,
    signoffExpectation: { sessionSeq: 7, statementDigest: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' },
    reason: 'Session review',
    action: 'approved',
    evidenceId: '5f0c1f0e-1111-4a1a-9a1a-000000000003',
    capturedAt: '2026-09-26T10:00:00.000Z',
    aiSystemId: 'loan-model',
    aiOutput: { recommendation: 'approve', confidence: 0.91 },
    decider: { freshness: null, credential: null, agent: null, id: 'acct:u-4821', kind: 'human' },
    contributions: null,
    links: null,
  },
  FIELDS,
);
const sparse = {
  evidenceId: '5f0c1f0e-1111-4a1a-9a1a-000000000004',
  schemaVersion: 'v1.0',
  aiSystemId: 'loan-model',
  aiOutput: { recommendation: 'decline' },
  action: 'decline',
  reason: 'Missing income proof',
  capturedAt: '2026-09-26T10:05:00.000Z',
  sequenceNumber: 4,
  decider: human(),
};
const I06 = objectInput(
  'I06',
  'Object-input vector over a v1.0 payload that omits contributions, links and signoffExpectation. Under the v1.0 hashed field set an ' +
    'absent key serializes as null, so its digest is I07\'s, where the three are written null (a writer writes every key).',
  sparse,
  FIELDS,
);
const I07 = objectInput(
  'I07',
  'Object-input vector: I06\'s payload with contributions, links and signoffExpectation written null. Same canonical bytes, same digest.',
  { ...sparse, contributions: null, links: null, signoffExpectation: null },
  FIELDS,
);
if (I06.expectedDigest !== I07.expectedDigest) stop('a missing key and a null one digest differently');
const legacy = {
  evidenceId: '5f0c1f0e-1111-4a1a-9a1a-000000000005',
  schemaVersion: 'v1.0',
  aiSystemId: 'loan-model',
  aiOutput: { recommendation: 'decline' },
  humanAction: 'declined',
  humanReason: 'Missing income proof',
  capturedAt: '2026-09-26T10:10:00.000Z',
  sequenceNumber: 5,
  aiBom: null,
  signoffExpectation: null,
};
const I08 = objectInput(
  'I08',
  'Object-input vector over a payload as a 0.7 release stored it, hashed under the eleven names of the revised set: humanAction, ' +
    'humanReason and aiBom are not hashed, and action, reason, decider, contributions and links serialize as null. This is not the digest ' +
    'such a record carries (that one recomputes under the 0.7 field set), which is why a 0.8.0 reader reports a 0.7 record digest_mismatch.',
  legacy,
  FIELDS,
);
const chain = new EvidenceChain();
chain.restore('prev');
const I03_LINK = chain.computeLink('cur');
if (I03_LINK !== 'ad8987a678cfb625a842b244500d1fc2d723e8ba49286301e74235e31f5cdbe3') stop('I03 changed');
if (I08.expectedDigest === sha256Hex(canonicalSerialize(legacy, [...FIELD_SET_0_7]))) stop('I08 digests alike under both sets');

emit({
  schemaVersion: 'v1.0',
  description:
    'Cross-language integrity-block parity: digest form + chainLink (Record §4.2, §5), over the v1.0 hashed field set as revised in 0.8.0 ' +
    '(Record §4.1)',
  notes: [
    'A vector carrying a `canonical` string is a LITERAL vector: it pins the digest FORM (SHA-256 over canonical bytes, lowercase bare hex) but does NOT exercise either canonicalizer, because the bytes reach it already canonicalized.',
    'A vector carrying an `input` object is an OBJECT-INPUT vector: each language canonicalizes `input` under `hashedFields` with its own serializer and must reproduce `expectedCanonical` before hashing. This is the only kind that can catch a canonicalizer divergence from the integrity corpus. `test_integrity_corpus_exercises_both_canonicalizers` asserts at least one exists, so the corpus cannot quietly lose it and go back to testing nothing.',
  ],
  source: 'Generated by scripts/generate-v1.0-integrity-vectors.ts.',
  vectors: [
    { id: 'I01', kind: 'digest', note: 'Literal vector — digest form only; never reaches a canonicalizer. See I04.', canonical: '{"a":1}', expectedDigest: sha256Hex('{"a":1}') },
    { id: 'I02', kind: 'chain-link', previousDigest: null, currentDigest: 'abc', expectedChainLink: null },
    { id: 'I03', kind: 'chain-link', previousDigest: 'prev', currentDigest: 'cur', expectedChainLink: I03_LINK },
    I04,
    I05,
    I06,
    I07,
    I08,
  ],
});
