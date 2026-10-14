/**
 * Generate vectors/store-generation-vectors.json: recognising the field set
 * a stored record was built under (Record §4.1, Verification §4.3).
 *
 *   - fieldSets  the three field sets, by name: `0.8` (the eleven names of
 *                v1.0 as revised in 0.8.0), `0.7` and `before-0.7`, the last
 *                two detection constants only;
 *   - records    an envelope, the generation its stored digest recomputes
 *                under (`recordFieldSetGeneration`: `0.8`, `0.7`,
 *                `before-0.7`, or `null`), the `fieldSet` fact a mismatch
 *                carries (`earlierFieldSet`), whether it verifies, and
 *                whether it predates the signature expectation;
 *   - stores     a store's records in sequence, whether a 0.8.0 process
 *                opens it (the first record decides: a store of an earlier
 *                generation is refused, `StoreSchemaOutdatedError`), and the
 *                later records a 0.8.0 reader reports as tampered
 *                (`digest_mismatch` at full severity, with the `fieldSet`
 *                fact: the fact explains, never excuses).
 *
 *   pnpm exec tsx scripts/generate-store-generation-vectors.ts > vectors/store-generation-vectors.json
 *
 * Every expected answer is written here from the specification, and the script
 * stops if the engine disagrees. The store rule belongs to the SDKs' store open and
 * scanner; the engine answers per record. The TS replay is
 * tests/cross-sdk/ts/store-generation-vectors.test.ts; the Python
 * recomputation is tests/cross-sdk/test_store_generation_vectors.py.
 */
import {
  FIELD_SET_0_7,
  FIELD_SET_BEFORE_0_7,
  canonicalSerialize,
  earlierFieldSet,
  recordFieldSetGeneration,
  recordPredatesSignoffExpectation,
  verifyEnvelope,
  type EvidenceEnvelope,
} from '@tzun/engine';
import { FIELDS, checker, emit, envelope, human, payload, sha256Hex } from './generate-vectors-shared';

const { agree } = checker('generate-store-generation-vectors');

/** An envelope whose stored digest is `p`'s under `fields`. */
const storedUnder = (p: Record<string, unknown>, fields: readonly string[]): EvidenceEnvelope => {
  const e = envelope(p);
  e.integrity.canonicalDigest = sha256Hex(canonicalSerialize(p, [...fields]));
  return e;
};
const id = (n: number) => `5f0c1f0e-7777-4a7a-9a7a-${String(n).padStart(12, '0')}`;

/** A payload as a release before 0.7.0 stored it: no signoffExpectation key. */
const before07 = (n: number) => ({
  evidenceId: id(n),
  schemaVersion: 'v1.0',
  aiSystemId: 'loan-model',
  aiOutput: { recommendation: 'approve' },
  humanAction: 'approved',
  humanReason: 'Income verified',
  capturedAt: `2026-06-0${n}T10:00:00.000Z`,
  sequenceNumber: n,
  aiBom: null,
});
/** A payload as a 0.7 release stored it. */
const of07 = (n: number) => ({ ...before07(n), capturedAt: `2026-09-0${n}T10:00:00.000Z`, signoffExpectation: null });
/** A payload a 0.8.0 writer builds. */
const of08 = (n: number, o: Record<string, unknown> = {}) =>
  payload({ evidenceId: id(n), aiSystemId: 'loan-model', aiOutput: { recommendation: 'approve' }, action: 'approved', reason: 'Income verified', capturedAt: `2026-10-0${n}T10:00:00.000Z`, sequenceNumber: n, decider: human(), ...o });

const R08 = storedUnder(of08(1), FIELDS);
const R07 = storedUnder(of07(1), FIELD_SET_0_7);
const RB07 = storedUnder(before07(1), FIELD_SET_BEFORE_0_7);
const tampered = storedUnder(of08(2), FIELDS);
tampered.payload.reason = 'Income verified twice';
/** A 0.8 record an attacker rewrote into the 0.7 field set, its digest recomputed: it now reads as a 0.7 record. */
const rewritten = (() => {
  const p = of08(2);
  const { action, reason, decider: _d, contributions: _c, links: _l, ...rest } = p;
  return storedUnder({ ...rest, humanAction: action, humanReason: reason, aiBom: null }, FIELD_SET_0_7);
})();
const R08b = storedUnder(of08(2), FIELDS);
const R07b = storedUnder(of07(2), FIELD_SET_0_7);
/** A 0.8 record whose null members were left out: a missing top-level key reads as null, so it is still 0.8. */
const sparse = (() => {
  const p = of08(1, { evidenceId: id(3), aiOutput: { recommendation: 'decline' } });
  delete p.contributions;
  delete p.links;
  delete p.signoffExpectation;
  return storedUnder(p, FIELDS);
})();

type Expect = { generation: string | null; fieldSet: string | null; verified: boolean; predatesSignoffExpectation: boolean };
const records: Array<{ case: string; envelope: EvidenceEnvelope; expect: Expect }> = [
  { case: 'a record a 0.8.0 writer built', envelope: R08, expect: { generation: '0.8', fieldSet: null, verified: true, predatesSignoffExpectation: false } },
  { case: 'a 0.8 record whose null members are left out (still 0.8)', envelope: sparse, expect: { generation: '0.8', fieldSet: null, verified: true, predatesSignoffExpectation: false } },
  { case: 'a record a 0.7 release built', envelope: R07, expect: { generation: '0.7', fieldSet: '0.7', verified: false, predatesSignoffExpectation: false } },
  { case: 'a record a release before 0.7.0 built', envelope: RB07, expect: { generation: 'before-0.7', fieldSet: 'before-0.7', verified: false, predatesSignoffExpectation: true } },
  { case: 'a 0.8 record edited after capture', envelope: tampered, expect: { generation: null, fieldSet: null, verified: false, predatesSignoffExpectation: false } },
  { case: 'a 0.8 record rewritten into the 0.7 field set, its digest recomputed (reads as 0.7: the fact explains, never excuses)', envelope: rewritten, expect: { generation: '0.7', fieldSet: '0.7', verified: false, predatesSignoffExpectation: false } },
];
for (const r of records) {
  agree(`records "${r.case}" generation`, recordFieldSetGeneration(r.envelope), r.expect.generation);
  agree(`records "${r.case}" fieldSet`, earlierFieldSet(r.envelope.payload, r.envelope.integrity.canonicalDigest), r.expect.fieldSet);
  agree(`records "${r.case}" verified`, verifyEnvelope(r.envelope).verified, r.expect.verified);
  agree(`records "${r.case}" fieldSet fact`, verifyEnvelope(r.envelope).fieldSet ?? null, r.expect.fieldSet);
  agree(`records "${r.case}" predates`, recordPredatesSignoffExpectation(r.envelope), r.expect.predatesSignoffExpectation);
}

type StoreExpect = { opens: boolean; generation: string; tampered: Array<{ index: number; fieldSet: string | null }> };
const stores: Array<{ case: string; envelopes: EvidenceEnvelope[]; expect: StoreExpect }> = [
  { case: 'a 0.8.0 store', envelopes: [R08, R08b], expect: { opens: true, generation: '0.8', tampered: [] } },
  { case: 'a 0.7 store (rebuilt, not continued)', envelopes: [R07, R07b], expect: { opens: false, generation: '0.7', tampered: [] } },
  { case: 'a store written before 0.7.0', envelopes: [RB07], expect: { opens: false, generation: 'before-0.7', tampered: [] } },
  { case: 'a 0.7 store a 0.8.0 process appended to (the first record decides)', envelopes: [R07, R08b], expect: { opens: false, generation: '0.7', tampered: [] } },
  { case: 'a 0.8.0 store a 0.7 process appended to', envelopes: [R08, R07b], expect: { opens: true, generation: '0.8', tampered: [{ index: 1, fieldSet: '0.7' }] } },
  { case: 'a 0.8.0 store holding a record rewritten into the 0.7 field set', envelopes: [R08, rewritten], expect: { opens: true, generation: '0.8', tampered: [{ index: 1, fieldSet: '0.7' }] } },
  { case: 'a 0.8.0 store holding a record edited after capture', envelopes: [R08, tampered], expect: { opens: true, generation: '0.8', tampered: [{ index: 1, fieldSet: null }] } },
];
for (const s of stores) {
  const generations = s.envelopes.map((e) => recordFieldSetGeneration(e));
  agree(`stores "${s.case}" first`, generations[0], s.expect.generation);
  agree(`stores "${s.case}" opens`, generations[0] === '0.8', s.expect.opens);
  const later = s.expect.opens
    ? s.envelopes.flatMap((e, index) => (index > 0 && generations[index] !== '0.8' ? [{ index, fieldSet: earlierFieldSet(e.payload, e.integrity.canonicalDigest) }] : []))
    : [];
  agree(`stores "${s.case}" tampered`, later, s.expect.tampered);
}

emit({
  description:
    'Recognising the field set a stored record was built under (Record §4.1): the generation of each record by recomputation, the ' +
    'fieldSet fact a digest mismatch carries (Verification §4.3), the first-record rule a 0.8.0 store open applies, and the later ' +
    'records a 0.8.0 reader reports as tampered.',
  source:
    'Generated by scripts/generate-store-generation-vectors.ts. Every expected answer is written in the script from the specification, and the ' +
    'script stops if the engine disagrees with one. The schema version a record names is not trusted: every record here names v1.0.',
  fieldSets: { '0.8': FIELDS, '0.7': [...FIELD_SET_0_7], 'before-0.7': [...FIELD_SET_BEFORE_0_7] },
  records,
  stores,
});
