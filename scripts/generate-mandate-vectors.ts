/**
 * Generate vectors/mandate-vectors.json: the answers every implementation of
 * mandates (Record §9.6 to §9.10) must give.
 *
 *   - documents         a document, why it is refused (`mandateDocumentViolation`:
 *                       `{ code, field }`, at signing unless `prepare` is
 *                       false), its canonical length and digest;
 *   - statements        a statement, whether it is well formed, its digest and
 *                       challenge (`tzun-signoff-mandate/1`, no signerName);
 *   - assertionDigests  an assertion and its digest (`null` when it has none):
 *                       W4's Ed25519 assertion, one ES256 signature as low S,
 *                       high S, non-minimal and long-form DER (one digest),
 *                       encodings of one byte string, signatures that are not DER;
 *   - predicates        a predicate, a payload (or its JSON text, where the
 *                       number's spelling matters), whether the predicate is well
 *                       formed, and what it evaluates to;
 *   - scope             a document and a payload, and `evaluateMandateScope`;
 *   - limits            a document and a payload, and `checkMandateLimits`;
 *   - consumption       a document, a set of records and the newest event body,
 *                       and `checkMandateConsumption`;
 *   - issuance          an envelope and its `mandate.issuance` row (`null`
 *                       when the row is not reported);
 *   - eventBodies       an event body, whether it is well formed and its
 *                       digest; the bodies a writer refuses;
 *   - claims            what a capture under a mandate claims (`planMandateClaim`)
 *                       or why it is refused;
 *   - lifecycle         revocation instants, successors, confirmations and expiry.
 *
 *   pnpm exec tsx scripts/generate-mandate-vectors.ts > vectors/mandate-vectors.json
 *
 * Every expected answer is written here from the specification, and the script
 * stops if the engine disagrees. The TS replay is tests/cross-sdk/ts/mandate-vectors.test.ts;
 * the Python recomputation is tests/cross-sdk/test_mandate_vectors.py.
 */
import { createHash } from 'node:crypto';
import {
  P256_ORDER,
  assertionDigest,
  buildMandateEventBody,
  canonicalSerializeValue,
  checkMandateConsumption,
  checkMandateIssuance,
  checkMandateLimits,
  evaluateMandateScope,
  evaluatePredicate,
  mandateConfirmationViolation,
  mandateDigest,
  mandateDocumentViolation,
  mandateEventBodyDigest,
  mandateExpiredAt,
  mandateStatementChallenge,
  mandateStatementDigest,
  mandateStatementViolation,
  planMandateClaim,
  predecessorPrincipalViolation,
  predicateViolation,
  revocationInstantViolation,
  type MandateDocument,
} from '@tzun/engine';
import {
  AGENT,
  AGENT_B,
  CLAIMS_ORIGIN,
  MODEL,
  MODEL_B,
  SPIFFE,
  W4_ASSERTION,
  W4_ASSERTION_DIGEST,
  W4_BLOCK,
  W4_CHALLENGE,
  W4_DOCUMENT,
  W4_MANDATE_DIGEST,
  W4_STATEMENT,
  W4_STATEMENT_DIGEST,
  agentDecider,
  assertionDigestOf,
  assertionPresenting,
  bom,
  checker,
  digestOf,
  emit,
  envelope,
  human,
  payload,
  prefixed,
  recordDigest,
  sha256Hex,
} from './generate-vectors-shared';

const { agree } = checker('generate-mandate-vectors');
agree('W4 mandate digest', W4_MANDATE_DIGEST, '26b1fbef903914e39cb45378b7f10648611c751c1b93624173bcfe7b7b9938da');
agree('W4 statement digest', W4_STATEMENT_DIGEST, '9a2e761fd633a06433c2e386fd2107112260da481db7c4c4b5795954a7e69492');
agree('W4 challenge', W4_CHALLENGE, 'KZTU75Uvu5IeVsZpIpEN1SDqskrp3rA3Dcwl8oMgUBM');
agree('W4 assertion digest', W4_ASSERTION_DIGEST, '79aafeb32c197be65d3b27c7b1cc469beff89e8650d1a84e02b437ec7937966d');

const doc = (edit: (d: Record<string, unknown>) => void = () => {}): Record<string, unknown> => {
  const d = JSON.parse(JSON.stringify(W4_DOCUMENT)) as Record<string, unknown>;
  edit(d);
  return d;
};
const at = (d: Record<string, unknown>, path: string[]): Record<string, unknown> =>
  path.reduce((o, k) => o[k] as Record<string, unknown>, d);

// ── documents ────────────────────────────────────────────────────────────

const documents: Array<{ case: string; document: unknown; prepare?: false; violation: { code: string; field: string } | null; byteLength?: number; digest?: string }> = [];
const docCase = (c: string, d: unknown, violation: { code: string; field: string } | null, prepare?: false) => {
  const entry: (typeof documents)[number] = { case: c, document: d, ...(prepare === false && { prepare }), violation };
  if (violation === null) {
    const canonical = canonicalSerializeValue(d);
    entry.byteLength = Buffer.byteLength(canonical);
    entry.digest = sha256Hex(canonical);
  }
  documents.push(entry);
};
const V = (code: string, field: string) => ({ code, field });
docCase('W4: the example document of Record §9.7, an opaque principal, no policy digest', W4_DOCUMENT, null);
docCase('no caps, no confirm, no review, no validity bounds, no record limit', doc((d) => {
  d.confirm = null;
  d.review = null;
  d.validity = { notBefore: null, notAfter: null };
  d.limits = { maxRecords: null, cumulative: null };
  at(d, ['scope']).predicates = null;
}), null);
docCase('a scope that restricts nothing (every set null)', doc((d) => {
  d.scope = { aiSystemIds: null, actions: null, models: null, predicates: null };
}), null);
docCase('a scope that permits nothing ([] is a set with no member)', doc((d) => {
  d.scope = { aiSystemIds: [], actions: [], models: [], predicates: null };
}), null);
docCase('a predicate path into a step\'s bill of materials (contributions is hashed)', doc((d) => {
  at(d, ['scope']).predicates = { temp: { op: 'eq', path: '/contributions/steps/0/aiBom/inferenceParameters/temperature', quant: null, value: 0 } };
}), null);
docCase('a successor naming its predecessor', doc((d) => {
  d.predecessor = digestOf('the predecessor mandate');
}), null);
docCase('a predicate path naming a member outside the hashed set (the restriction)', doc((d) => {
  at(d, ['scope']).predicates = { sv: { op: 'eq', path: '/schemaVersion', quant: null, value: 'v1.0' } };
}), V('restriction_failed', 'document.schemaVersion'));
docCase('a cap path naming a member outside the hashed set', doc((d) => {
  at(d, ['limits']).cumulative = { paid: { path: '/nonRepudiation/x', max: 10 } };
}), V('restriction_failed', 'document.schemaVersion'));
docCase('a schema version the registry does not hold (v1.1)', doc((d) => {
  d.schemaVersion = 'v1.1';
}), V('restriction_failed', 'document.schemaVersion'));
docCase('limits.cumulative {} (write null)', doc((d) => {
  at(d, ['limits']).cumulative = {};
}), V('empty_cumulative', 'document.limits.cumulative'));
docCase('a cap name with a space', doc((d) => {
  at(d, ['limits']).cumulative = { 'paid total': { path: '/aiOutput/amountMinor', max: 10 } };
}), V('invalid_cap', 'document.limits.cumulative.paid total'));
docCase('17 caps', doc((d) => {
  at(d, ['limits']).cumulative = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`cap${String(i).padStart(2, '0')}`, { path: '/aiOutput/amountMinor', max: 10 }]));
}), V('invalid_cap', 'document.limits.cumulative'));
docCase('a cap with no max', doc((d) => {
  at(d, ['limits']).cumulative = { paid: { path: '/aiOutput/amountMinor' } };
}), V('invalid_cap', 'document.limits.cumulative.paid'));
docCase('a cap path that is not a JSON Pointer', doc((d) => {
  at(d, ['limits']).cumulative = { paid: { path: 'aiOutput/amountMinor', max: 10 } };
}), V('invalid_cap', 'document.limits.cumulative.paid'));
docCase('over 16 KiB of canonical bytes', doc((d) => {
  at(d, ['scope']).aiSystemIds = Array.from({ length: 600 }, (_, i) => `claims-triage-system-${String(i).padStart(4, '0')}`);
}), V('document_too_large', 'document'));
docCase('a principal that is an email address', doc((d) => {
  at(d, ['principal']).signer = 'jane@example.com';
}), V('invalid_principal', 'document.principal.signer'));
docCase('a prefixed principal credential', doc((d) => {
  at(d, ['principal']).credential = `sha256:${digestOf('credential')}`;
}), V('invalid_principal', 'document.principal.credential'));
docCase('agents unsorted (a set is written sorted)', doc((d) => {
  d.agents = [`desc:${AGENT}`, `desc:${AGENT_B}`].sort().reverse();
}), V('invalid_document', 'document.agents'));
docCase('an agent named by an acct identifier', doc((d) => {
  d.agents = ['acct:u-4821'];
}), V('invalid_document', 'document.agents'));
docCase('a string outside printable ASCII', doc((d) => {
  at(d, ['scope']).actions = ['approve', 'réfer'];
}), V('invalid_document', 'document.scope.actions'));
docCase('a negative integer', doc((d) => {
  at(d, ['review']).maxAgeMs = -1;
}), V('invalid_document', 'document.review.maxAgeMs'));
docCase('a fraction', doc((d) => {
  at(d, ['limits', 'cumulative', 'paid']).max = 2.5;
}), V('invalid_document', 'document.limits.cumulative.paid.max'));
docCase('a key missing (every key is written, null where it does not apply)', doc((d) => {
  delete d.review;
}), V('invalid_document', 'document'));
docCase('the version tag of another document', doc((d) => {
  d.v = 'tzun-mandate/2';
}), V('invalid_document', 'document.v'));
docCase('an uppercase mandate id', doc((d) => {
  d.mandateId = (d.mandateId as string).toUpperCase();
}), V('invalid_document', 'document.mandateId'));
docCase('delegation allowed (no sub-mandates in this version)', doc((d) => {
  d.delegation = { allowed: true, maxDepth: 1, attenuation: 'subset' };
}), V('invalid_document', 'document.delegation'));
docCase('delegation allowed, read as a reader reads a document (no prepare rules)', doc((d) => {
  d.delegation = { allowed: true, maxDepth: 1, attenuation: 'subset' };
}), null, false);
docCase('a parent named', doc((d) => {
  d.parent = digestOf('a parent mandate');
}), V('invalid_document', 'document.parent'));
docCase('a validity window that ends before it begins', doc((d) => {
  d.validity = { notBefore: '2026-12-31T00:00:00.000Z', notAfter: '2026-10-01T00:00:00.000Z' };
}), V('invalid_document', 'document.validity'));
docCase('a validity window that ends before it begins, read with no prepare rules', doc((d) => {
  d.validity = { notBefore: '2026-12-31T00:00:00.000Z', notAfter: '2026-10-01T00:00:00.000Z' };
}), null, false);
docCase('an instant without milliseconds', doc((d) => {
  d.validity = { notBefore: '2026-10-01T00:00:00Z', notAfter: null };
}), V('invalid_document', 'document.validity'));
docCase('an instant that is not a real date (30 February)', doc((d) => {
  d.validity = { notBefore: '2026-02-30T00:00:00.000Z', notAfter: null };
}), V('invalid_document', 'document.validity'));
docCase('an eq predicate on null (a null subject is undeterminable)', doc((d) => {
  at(d, ['scope']).predicates = { cap: { op: 'eq', path: '/aiOutput/x', quant: null, value: null } };
}), V('invalid_predicate', 'document.scope.predicates.cap'));
docCase('a predicate path with ~2', doc((d) => {
  at(d, ['scope']).predicates = { cap: { op: 'eq', path: '/aiOutput/a~2b', quant: null, value: 1 } };
}), V('invalid_predicate', 'document.scope.predicates.cap'));
docCase('a predicate name with a space', doc((d) => {
  at(d, ['scope']).predicates = { 'the cap': { op: 'le', path: '/aiOutput/amountMinor', quant: null, value: 1 } };
}), V('invalid_predicate', 'document.scope.predicates.the cap'));
docCase('a confirm predicate with an unknown op', doc((d) => {
  d.confirm = { fraud: { op: 'is', path: '/aiOutput/fraudFlag', quant: null, value: true } };
}), V('invalid_predicate', 'document.confirm.fraud'));
docCase('65 predicates', doc((d) => {
  at(d, ['scope']).predicates = Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`p${String(i).padStart(2, '0')}`, { op: 'le', path: '/aiOutput/amountMinor', quant: null, value: i }]));
}), V('invalid_document', 'document'));
docCase('scope.predicates {} (write null)', doc((d) => {
  at(d, ['scope']).predicates = {};
}), V('invalid_document', 'document.scope.predicates'));
for (const d of documents) {
  const got = mandateDocumentViolation(d.document, d.prepare === false ? { prepare: false } : {});
  agree(`documents "${d.case}"`, got && { code: got.code, field: got.field }, d.violation);
  if (d.violation === null) agree(`documents "${d.case}" digest`, mandateDigest(d.document), d.digest);
}
agree('W4 document bytes', documents[0].byteLength, 921);

// ── statements ───────────────────────────────────────────────────────────

const statements = [
  { case: 'W4\'s statement', statement: W4_STATEMENT, wellFormed: true },
  { case: 'no notBefore reference', statement: { ...W4_STATEMENT, notBefore: 'none' }, wellFormed: true },
  { case: 'a policy digest', statement: { ...W4_STATEMENT, policyDigest: digestOf('policy') }, wellFormed: true },
  { case: 'a statement carrying signerName (a printed name)', statement: { ...W4_STATEMENT, signerName: 'Sm9zw6kgw4FsdmFyZXo' }, wellFormed: false },
  { case: 'a signer that is an email address', statement: { ...W4_STATEMENT, signer: 'jane@example.com' }, wellFormed: false },
  { case: 'a signer kind other than human', statement: { ...W4_STATEMENT, signerKind: 'agent' }, wellFormed: false },
  { case: 'a meaning other than responsibility', statement: { ...W4_STATEMENT, meaning: 'approval' }, wellFormed: false },
  { case: 'mode batch', statement: { ...W4_STATEMENT, mode: 'batch' }, wellFormed: false },
  { case: 'an uppercase mandate digest', statement: { ...W4_STATEMENT, mandateDigest: W4_MANDATE_DIGEST.toUpperCase() }, wellFormed: false },
  { case: 'a notBefore on eip155:01', statement: { ...W4_STATEMENT, notBefore: W4_STATEMENT.notBefore.replace('eip155:1@', 'eip155:01@') }, wellFormed: false },
  { case: 'policyDigest null (write none)', statement: { ...W4_STATEMENT, policyDigest: null }, wellFormed: false },
].map((s) => {
  const digest = s.wellFormed ? sha256Hex(canonicalSerializeValue(s.statement)) : null;
  return { ...s, digest, challenge: digest === null ? null : createHash('sha256').update('tzun-signoff-v1' + digest).digest('base64url') };
});
for (const s of statements) {
  agree(`statements "${s.case}" well formed`, mandateStatementViolation(s.statement) === null, s.wellFormed);
  agree(`statements "${s.case}" digest`, mandateStatementDigest(s.statement), s.digest);
  if (s.digest !== null) agree(`statements "${s.case}" challenge`, mandateStatementChallenge(s.digest), s.challenge);
}

// ── assertion digests ───────────────────────────────────────────────────

function derInteger(value: bigint, pad = 0): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let body = Buffer.from(hex, 'hex');
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
  body = Buffer.concat([Buffer.alloc(pad), body]);
  return Buffer.concat([Buffer.from([0x02, body.length]), body]);
}
function der(r: bigint, s: bigint, opts: { padR?: number; longLength?: boolean } = {}): Buffer {
  const body = Buffer.concat([derInteger(r, opts.padR ?? 0), derInteger(s)]);
  return Buffer.concat([Buffer.from([0x30]), opts.longLength ? Buffer.from([0x81, body.length]) : Buffer.from([body.length]), body]);
}
const R = BigInt('0x' + createHash('sha256').update('mandate vector r').digest('hex')) % P256_ORDER;
const sHigh = P256_ORDER - (BigInt('0x' + createHash('sha256').update('mandate vector s').digest('hex')) % (P256_ORDER >> BigInt(1)));
const sLow = P256_ORDER - sHigh;
const authData = Buffer.concat([createHash('sha256').update('rp.example').digest(), Buffer.from([0x05, 0, 0, 0, 9])]);
const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: W4_CHALLENGE, origin: 'https://rp.example' }));
const es256 = (sig: Buffer, encode: (b: Buffer) => string = (b) => b.toString('base64url')) => ({
  signature: encode(sig), credentialKeyId: 'credential-1', algorithm: 'ES256', authenticatorData: encode(authData), clientDataJSON: encode(clientData),
});
const lowS = der(R, sLow);
const lowDigest = assertionDigestOf({ authenticatorData: authData.toString('base64url'), clientDataJSON: clientData.toString('base64url'), signature: '' }, lowS);
const assertionDigests = [
  { case: 'W4\'s Ed25519 assertion (the RFC 8037 Appendix A key over W4\'s challenge)', assertion: W4_ASSERTION, digest: W4_ASSERTION_DIGEST },
  { case: 'ES256, minimal DER, low S', assertion: es256(lowS), digest: lowDigest },
  { case: 'ES256, the same signature with high S', assertion: es256(der(R, sHigh)), digest: lowDigest },
  { case: 'ES256, a non-minimal integer encoding', assertion: es256(der(R, sLow, { padR: 1 })), digest: lowDigest },
  { case: 'ES256, a long-form sequence length', assertion: es256(der(R, sLow, { longLength: true })), digest: lowDigest },
  { case: 'ES256, every member in padded standard base64', assertion: es256(lowS, (b) => b.toString('base64')), digest: lowDigest },
  { case: 'ES256, r||s raw (not DER): refused', assertion: es256(Buffer.concat([Buffer.from(R.toString(16).padStart(64, '0'), 'hex'), Buffer.from(sLow.toString(16).padStart(64, '0'), 'hex')])), digest: null },
  { case: 'ES256, trailing bytes after the sequence: refused', assertion: es256(Buffer.concat([lowS, Buffer.from([0])])), digest: null },
  { case: 'ES256, s = 0: refused', assertion: es256(der(R, BigInt(0))), digest: null },
  { case: 'ES256, r = n: refused', assertion: es256(der(P256_ORDER, sLow)), digest: null },
  { case: 'an algorithm this version does not read (RS256)', assertion: { ...es256(lowS), algorithm: 'RS256' }, digest: null },
  { case: 'no authenticatorData', assertion: { ...es256(lowS), authenticatorData: undefined }, digest: null },
  { case: 'base64 and base64url mixed in one value', assertion: { ...es256(lowS), clientDataJSON: '+_' + clientData.toString('base64url') }, digest: null },
].map((a) => ({ ...a, assertion: JSON.parse(JSON.stringify(a.assertion)) as Record<string, unknown> }));
for (const a of assertionDigests) agree(`assertionDigests "${a.case}"`, assertionDigest(a.assertion), a.digest);

// ── predicates ──────────────────────────────────────────────────────────

type Outcome = 'true' | 'false' | 'undeterminable';
const predicates: Array<{ case: string; predicate: unknown; payload?: unknown; payloadJson?: string; wellFormed: boolean; outcome: Outcome }> = [];
const pr = (path: string, op: string, value: unknown, quant: string | null = null) => ({ path, op, value, quant });
const evalCase = (c: string, predicate: unknown, aiOutput: unknown, outcome: Outcome, wellFormed = true) =>
  predicates.push({ case: c, predicate, payload: { aiOutput }, wellFormed, outcome });
const jsonCase = (c: string, predicate: unknown, payloadJson: string, outcome: Outcome) => predicates.push({ case: c, predicate, payloadJson, wellFormed: true, outcome });

evalCase('eq on a string, equal', pr('/aiOutput/s', 'eq', 'approve'), { s: 'approve' }, 'true');
evalCase('eq on a string, unequal', pr('/aiOutput/s', 'eq', 'approve'), { s: 'refer' }, 'false');
evalCase('eq on an integer', pr('/aiOutput/n', 'eq', 3), { n: 3 }, 'true');
evalCase('eq on a boolean', pr('/aiOutput/b', 'eq', true), { b: true }, 'true');
evalCase('eq across types: 1 is never true', pr('/aiOutput/b', 'eq', true), { b: 1 }, 'false');
evalCase('eq across types: true is never 1', pr('/aiOutput/n', 'eq', 1), { n: true }, 'false');
evalCase('eq across types: "3" is not 3', pr('/aiOutput/n', 'eq', 3), { n: '3' }, 'false');
evalCase('ne across types', pr('/aiOutput/n', 'ne', 3), { n: '3' }, 'true');
evalCase('ne on an equal string', pr('/aiOutput/s', 'ne', 'approve'), { s: 'approve' }, 'false');
evalCase('eq on an object subject', pr('/aiOutput/o', 'eq', 1), { o: { n: 1 } }, 'undeterminable');
evalCase('eq on a fraction', pr('/aiOutput/n', 'eq', 1), { n: 1.5 }, 'undeterminable');
evalCase('eq on a negative integer (not a predicate integer)', pr('/aiOutput/n', 'eq', 1), { n: -1 }, 'undeterminable');
evalCase('lt', pr('/aiOutput/n', 'lt', 5), { n: 4 }, 'true');
evalCase('lt at the bound', pr('/aiOutput/n', 'lt', 5), { n: 5 }, 'false');
evalCase('le at the bound', pr('/aiOutput/n', 'le', 5), { n: 5 }, 'true');
evalCase('gt', pr('/aiOutput/n', 'gt', 5), { n: 5 }, 'false');
evalCase('ge at the bound', pr('/aiOutput/n', 'ge', 5), { n: 5 }, 'true');
evalCase('lt on 2^53 - 1', pr('/aiOutput/n', 'lt', 9007199254740991), { n: 9007199254740990 }, 'true');
evalCase('le on a string "3"', pr('/aiOutput/n', 'le', 5), { n: '3' }, 'undeterminable');
evalCase('le on a boolean', pr('/aiOutput/n', 'le', 5), { n: false }, 'undeterminable');
evalCase('in', pr('/aiOutput/s', 'in', ['approve', 'refer']), { s: 'refer' }, 'true');
evalCase('in, absent', pr('/aiOutput/s', 'in', ['approve', 'refer']), { s: 'deny' }, 'false');
evalCase('notIn', pr('/aiOutput/s', 'notIn', ['approve', 'refer']), { s: 'deny' }, 'true');
evalCase('in on an integer', pr('/aiOutput/s', 'in', ['1', '2']), { s: 1 }, 'undeterminable');
evalCase('prefix', pr('/aiOutput/s', 'prefix', 'claims/'), { s: 'claims/auto' }, 'true');
evalCase('prefix, absent', pr('/aiOutput/s', 'prefix', 'claims/'), { s: 'claim/auto' }, 'false');
evalCase('prefix of an empty string (always true for a string)', pr('/aiOutput/s', 'prefix', ''), { s: 'x' }, 'true');
evalCase('glob: * within a segment', pr('/aiOutput/s', 'glob', ['claims/*']), { s: 'claims/auto' }, 'true');
evalCase('glob: * does not cross /', pr('/aiOutput/s', 'glob', ['claims/*']), { s: 'claims/auto/1' }, 'false');
evalCase('glob: ** across segments', pr('/aiOutput/s', 'glob', ['claims/**/final']), { s: 'claims/a/b/final' }, 'true');
evalCase('glob: ** matching no segment', pr('/aiOutput/s', 'glob', ['claims/**/final']), { s: 'claims/final' }, 'true');
evalCase('glob: ? matches one astral code point', pr('/aiOutput/s', 'glob', ['claims/?']), { s: 'claims/\u{1F600}' }, 'true');
evalCase('glob: ? does not match two UTF-16 units of one character twice', pr('/aiOutput/s', 'glob', ['claims/??']), { s: 'claims/\u{1F600}' }, 'false');
evalCase('glob: ? does not match /', pr('/aiOutput/s', 'glob', ['a?b']), { s: 'a/b' }, 'false');
evalCase('glob: the whole subject must match', pr('/aiOutput/s', 'glob', ['claims']), { s: 'claims/auto' }, 'false');
evalCase('glob: one of several patterns', pr('/aiOutput/s', 'glob', ['auto/*', 'claims/*']), { s: 'claims/x' }, 'true');
evalCase('glob: a pathological pattern within the limits', pr('/aiOutput/s', 'glob', ['a*a*a*a*a*a*a*a*a*a*b']), { s: 'a'.repeat(4096) }, 'false');
evalCase('a string subject of 4,096 code points', pr('/aiOutput/s', 'prefix', 'a'), { s: 'a'.repeat(4096) }, 'true');
evalCase('a string subject of 4,097 code points', pr('/aiOutput/s', 'prefix', 'a'), { s: 'a'.repeat(4097) }, 'undeterminable');
evalCase('4,096 astral code points (8,192 UTF-16 units) are within the limit', pr('/aiOutput/s', 'ne', 'x'), { s: '\u{1F600}'.repeat(4096) }, 'true');
evalCase('4,097 astral code points', pr('/aiOutput/s', 'ne', 'x'), { s: '\u{1F600}'.repeat(4097) }, 'undeterminable');
evalCase('all over an array, every element true', pr('/aiOutput/a', 'le', 5, 'all'), { a: [1, 2, 3] }, 'true');
evalCase('all over an array, one false', pr('/aiOutput/a', 'le', 5, 'all'), { a: [1, 9, 'x'] }, 'false');
evalCase('all over an array, one undeterminable and none false', pr('/aiOutput/a', 'le', 5, 'all'), { a: [1, 'x'] }, 'undeterminable');
evalCase('all over [] (vacuous)', pr('/aiOutput/a', 'le', 5, 'all'), { a: [] }, 'true');
evalCase('any over an array, one true', pr('/aiOutput/a', 'eq', 'x', 'any'), { a: ['y', 3, 'x'] }, 'true');
evalCase('any over an array, one undeterminable and none true', pr('/aiOutput/a', 'gt', 5, 'any'), { a: [1, 'x'] }, 'undeterminable');
evalCase('any over []', pr('/aiOutput/a', 'gt', 5, 'any'), { a: [] }, 'false');
evalCase('quant null over an array', pr('/aiOutput/a', 'le', 5), { a: [1] }, 'undeterminable');
evalCase('quant all over a non-array', pr('/aiOutput/a', 'le', 5, 'all'), { a: 1 }, 'undeterminable');
evalCase('an array of 10,000 elements', pr('/aiOutput/a', 'le', 5, 'all'), { a: Array(10000).fill(1) }, 'true');
evalCase('an array of 10,001 elements', pr('/aiOutput/a', 'le', 5, 'all'), { a: Array(10001).fill(1) }, 'undeterminable');
evalCase('a path that resolves to nothing', pr('/aiOutput/missing', 'eq', 1), { n: 1 }, 'undeterminable');
evalCase('a path that resolves to null', pr('/aiOutput/n', 'eq', 1), { n: null }, 'undeterminable');
evalCase('array index 0', pr('/aiOutput/a/0', 'eq', 'x'), { a: ['x', 'y'] }, 'true');
evalCase('array index 01 (resolves to nothing)', pr('/aiOutput/a/01', 'eq', 'y'), { a: ['x', 'y'] }, 'undeterminable');
evalCase('array index - (resolves to nothing)', pr('/aiOutput/a/-', 'eq', 'y'), { a: ['x', 'y'] }, 'undeterminable');
evalCase('array index past the end', pr('/aiOutput/a/2', 'eq', 'y'), { a: ['x', 'y'] }, 'undeterminable');
evalCase('~1 unescapes to /', pr('/aiOutput/a~1b', 'eq', 1), { 'a/b': 1 }, 'true');
evalCase('~0 unescapes to ~', pr('/aiOutput/m~0n', 'eq', 1), { 'm~n': 1 }, 'true');
evalCase('~01 is ~1, not /', pr('/aiOutput/a~01', 'eq', 1), { 'a~1': 1, 'a/': 2 }, 'true');
evalCase('an empty token names the empty key', pr('/aiOutput/', 'eq', 1), { '': 1 }, 'true');
predicates.push({
  case: 'a path into a step\'s bill of materials',
  predicate: pr('/contributions/steps/0/aiBom/inferenceParameters/temperature', 'eq', 0),
  payload: { contributions: { pipeline: null, externals: [], steps: [{ aiBom: { ...bom(MODEL, { temperature: 0, topP: null, maxTokens: 800, seed: null, stopSequences: null }) } }] } },
  wellFormed: true,
  outcome: 'true',
});
jsonCase('1.0 is the integer 1', pr('/aiOutput/n', 'eq', 1), '{"aiOutput":{"n":1.0}}', 'true');
jsonCase('1e0 is the integer 1', pr('/aiOutput/n', 'le', 1), '{"aiOutput":{"n":1e0}}', 'true');
jsonCase('5.000 against lt 5', pr('/aiOutput/n', 'lt', 5), '{"aiOutput":{"n":5.000}}', 'false');
jsonCase('2e2 is the integer 200', pr('/aiOutput/n', 'eq', 200), '{"aiOutput":{"n":2e2}}', 'true');
jsonCase('-0 is the integer 0', pr('/aiOutput/n', 'eq', 0), '{"aiOutput":{"n":-0}}', 'true');
jsonCase('1.5e0 is not an integer', pr('/aiOutput/n', 'le', 5), '{"aiOutput":{"n":1.5e0}}', 'undeterminable');
for (const [c, p] of [
  ['eq on null (refused at prepare)', pr('/aiOutput/n', 'eq', null)],
  ['lt on a negative integer', pr('/aiOutput/n', 'lt', -1)],
  ['lt on a fraction', pr('/aiOutput/n', 'lt', 1.5)],
  ['lt on a string', pr('/aiOutput/n', 'lt', '5')],
  ['in with an unsorted set', pr('/aiOutput/s', 'in', ['refer', 'approve'])],
  ['in with a repeated element', pr('/aiOutput/s', 'in', ['approve', 'approve'])],
  ['in with an empty set', pr('/aiOutput/s', 'in', [])],
  ['in with 65 elements', pr('/aiOutput/s', 'in', Array.from({ length: 65 }, (_, i) => `v${String(i).padStart(2, '0')}`))],
  ['glob with a pattern of 257 characters', pr('/aiOutput/s', 'glob', ['a'.repeat(257)])],
  ['glob with an empty pattern', pr('/aiOutput/s', 'glob', [''])],
  ['a path with ~2', pr('/aiOutput/a~2', 'eq', 1)],
  ['a path ending in ~', pr('/aiOutput/a~', 'eq', 1)],
  ['a path that does not begin with /', pr('aiOutput/n', 'eq', 1)],
  ['an op outside the ten', pr('/aiOutput/n', 'is', 1)],
  ['a quant outside null, all and any', pr('/aiOutput/a', 'le', 1, 'some')],
  ['a member outside the four', { ...pr('/aiOutput/n', 'eq', 1), note: 'x' }],
  ['eq on a string outside printable ASCII', pr('/aiOutput/s', 'eq', 'réfer')],
] as const) {
  predicates.push({ case: c, predicate: p, payload: { aiOutput: { n: 1, s: 'approve', a: [1] } }, wellFormed: false, outcome: 'undeterminable' });
}
for (const p of predicates) {
  const subject = p.payloadJson !== undefined ? JSON.parse(p.payloadJson) : p.payload;
  agree(`predicates "${p.case}" well formed`, predicateViolation(p.predicate) === null, p.wellFormed);
  agree(`predicates "${p.case}"`, evaluatePredicate(p.predicate, subject), p.outcome);
}

// ── scope and limits ────────────────────────────────────────────────────

const CLAIM_OUTPUT = { amountMinor: 120000, fraudFlag: false, recommendation: 'approve' };
const mandated = (o: Record<string, unknown> = {}, expectation: Record<string, unknown> = {}) =>
  payload({
    aiSystemId: 'claims-triage-v4',
    aiOutput: CLAIM_OUTPUT,
    action: 'approve',
    reason: 'Policy active; invoice matches the repair estimate',
    capturedAt: '2026-11-20T10:14:50.000Z',
    decider: agentDecider('agent-mandated'),
    contributions: { pipeline: null, externals: [], steps: [{ role: 'propose', actor: { kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT }, aiBom: bom(), inputs: [], output: prefixed(CLAIM_OUTPUT), verdict: null, reason: null, prev: null }] },
    signoffExpectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm: false, ...expectation },
    ...o,
  });
const scopeResult = (verdict: string, failures: unknown[] = [], undeterminable: unknown[] = [], agentInMandate = true, confirmationEvaded = false) => ({
  verdict, failures, undeterminable, agentInMandate, confirmationEvaded,
});
const withSteps = (steps: Array<Record<string, unknown>>) => ({ pipeline: null, externals: [], steps });
const scope = [
  { case: 'the record W6 describes: within', document: W4_DOCUMENT, payload: mandated(), expect: scopeResult('within') },
  { case: 'a decider that is not one of the agents', document: W4_DOCUMENT, payload: mandated({ decider: agentDecider('agent-mandated', AGENT_B) }), expect: scopeResult('outside', [{ constraint: 'agents' }], [], false) },
  { case: 'a decider named by its desc reference, its id another scheme', document: W4_DOCUMENT, payload: mandated({ decider: { ...agentDecider('agent-mandated'), id: SPIFFE } }), expect: scopeResult('within') },
  { case: 'an aiSystemId outside the set', document: W4_DOCUMENT, payload: mandated({ aiSystemId: 'claims-triage-v5' }), expect: scopeResult('outside', [{ constraint: 'aiSystemIds' }]) },
  { case: 'an action outside the set', document: W4_DOCUMENT, payload: mandated({ action: 'deny' }), expect: scopeResult('outside', [{ constraint: 'actions' }]) },
  {
    case: 'a reviewer\'s model outside scope.models (a model outside scope may not review either)',
    document: W4_DOCUMENT,
    payload: mandated({ contributions: withSteps([
      { role: 'propose', actor: null, aiBom: bom(), inputs: [], output: prefixed(CLAIM_OUTPUT), verdict: null, reason: null, prev: null },
      { role: 'review', actor: null, aiBom: bom(MODEL_B), inputs: [prefixed(CLAIM_OUTPUT)], output: prefixed('review'), verdict: 'approve', reason: null, prev: prefixed('step 0') },
    ]) }),
    expect: scopeResult('outside', [{ constraint: 'models' }]),
  },
  {
    case: 'no step records a model while scope.models is set',
    document: W4_DOCUMENT,
    payload: mandated({ contributions: null }),
    expect: scopeResult('undeterminable', [], [{ constraint: 'models' }]),
  },
  { case: 'a scope predicate that fails (an amount over the per-decision cap)', document: W4_DOCUMENT, payload: mandated({ aiOutput: { ...CLAIM_OUTPUT, amountMinor: 600000 } }), expect: scopeResult('outside', [{ constraint: 'predicate', name: 'cap' }]) },
  {
    case: 'a scope predicate that is undeterminable (the amount missing)',
    document: W4_DOCUMENT,
    payload: mandated({ aiOutput: { fraudFlag: false, recommendation: 'approve' } }),
    expect: scopeResult('undeterminable', [], [{ constraint: 'predicate', name: 'cap' }]),
  },
  { case: 'confirm false while a confirm predicate holds: confirmation evaded', document: W4_DOCUMENT, payload: mandated({ aiOutput: { ...CLAIM_OUTPUT, fraudFlag: true } }), expect: scopeResult('within', [], [], true, true) },
  { case: 'confirm true while a confirm predicate holds', document: W4_DOCUMENT, payload: mandated({ aiOutput: { ...CLAIM_OUTPUT, fraudFlag: true } }, { confirm: true }), expect: scopeResult('within') },
  {
    case: 'confirm false while the confirm predicate is undeterminable',
    document: W4_DOCUMENT,
    payload: mandated({ aiOutput: { amountMinor: 120000, recommendation: 'approve' } }),
    expect: scopeResult('undeterminable', [], [{ constraint: 'confirm', name: 'fraud' }]),
  },
  { case: 'a record of a schema version the registry does not hold: the restriction cannot be applied', document: W4_DOCUMENT, payload: mandated({ schemaVersion: 'v9.9' }), expect: scopeResult('undeterminable', [], [{ constraint: 'restriction' }]) },
  {
    case: 'several constraints failing at once',
    document: W4_DOCUMENT,
    payload: mandated({ aiSystemId: 'other', action: 'deny', aiOutput: { ...CLAIM_OUTPUT, amountMinor: 600000 } }),
    expect: scopeResult('outside', [{ constraint: 'aiSystemIds' }, { constraint: 'actions' }, { constraint: 'predicate', name: 'cap' }]),
  },
];
for (const s of scope) agree(`scope "${s.case}"`, evaluateMandateScope(s.document, s.payload), s.expect);

const noCaps = doc((d) => {
  d.limits = { maxRecords: 3, cumulative: null };
});
const limits = [
  { case: 'slot 41, total 5,230,000 (W6)', document: W4_DOCUMENT, payload: mandated(), expect: { valid: true, slot: 41, totals: { paid: 5230000 } } },
  { case: 'slot 10,001 of 10,000', document: W4_DOCUMENT, payload: mandated({}, { mandateSeq: 10001 }), expect: { valid: false, reason: 'mandate_limit_exceeded', slot: 10001, totals: { paid: 5230000 } } },
  { case: 'a total below the record\'s own value', document: W4_DOCUMENT, payload: mandated({}, { totals: { paid: 100000 } }), expect: { valid: false, reason: 'mandate_limit_exceeded', slot: 41, totals: { paid: 100000 } } },
  { case: 'a total over the cap', document: W4_DOCUMENT, payload: mandated({}, { totals: { paid: 250000001 } }), expect: { valid: false, reason: 'mandate_limit_exceeded', slot: 41, totals: { paid: 250000001 } } },
  { case: 'a total at the cap', document: W4_DOCUMENT, payload: mandated({}, { totals: { paid: 250000000 } }), expect: { valid: true, slot: 41, totals: { paid: 250000000 } } },
  { case: 'totals null while the document has a cap', document: W4_DOCUMENT, payload: mandated({}, { totals: null }), expect: { valid: false, reason: 'mandate_totals_malformed', slot: 41, totals: null } },
  { case: 'totals naming another cap', document: W4_DOCUMENT, payload: mandated({}, { totals: { spent: 5230000 } }), expect: { valid: false, reason: 'mandate_totals_malformed', slot: 41, totals: { spent: 5230000 } } },
  { case: 'totals with an extra cap', document: W4_DOCUMENT, payload: mandated({}, { totals: { paid: 5230000, spent: 1 } }), expect: { valid: false, reason: 'mandate_totals_malformed', slot: 41, totals: { paid: 5230000, spent: 1 } } },
  { case: 'the value at the cap path is a string', document: W4_DOCUMENT, payload: mandated({ aiOutput: { ...CLAIM_OUTPUT, amountMinor: '120000' } }), expect: { valid: false, reason: 'mandate_totals_malformed', slot: 41, totals: { paid: 5230000 } } },
  { case: 'no caps, totals null, within the record limit', document: noCaps, payload: mandated({}, { mandateSeq: 3, totals: null }), expect: { valid: true, slot: 3, totals: null } },
  { case: 'no caps, totals written', document: noCaps, payload: mandated({}, { mandateSeq: 3 }), expect: { valid: false, reason: 'mandate_totals_malformed', slot: 3, totals: { paid: 5230000 } } },
  { case: 'slot 0', document: W4_DOCUMENT, payload: mandated({}, { mandateSeq: 0 }), expect: { valid: false, reason: 'mandate_totals_malformed' } },
];
for (const l of limits) agree(`limits "${l.case}"`, checkMandateLimits(l.document, l.payload), l.expect);

// ── consumption ─────────────────────────────────────────────────────────

const slot = (mandateSeq: number, amountMinor: unknown, paid: number) =>
  envelope(mandated({ aiOutput: { ...CLAIM_OUTPUT, amountMinor } }, { mandateSeq, totals: { paid } }));
const AMOUNTS = [120000, 250000, 205000];
const run = [slot(1, AMOUNTS[0], 120000), slot(2, AMOUNTS[1], 370000), slot(3, AMOUNTS[2], 575000)];
const eventOf = (used: number, paid: number) => ({ v: 'tzun-mandate-event/1', event: 'revoked', mandateDigest: W4_MANDATE_DIGEST, record: digestOf('revocation'), successor: null, used, totals: { paid } });
const consumption = [
  { case: 'slots 1 to 3, every total stepping by its record\'s value', envelopes: run, expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 3, beyondEvent: [], complete: null } },
  { case: 'the records in another order', envelopes: [run[2], run[0], run[1]], expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 3, beyondEvent: [], complete: null } },
  { case: 'slot 2 deleted: a gap, and the amount it leaves unexplained', envelopes: [run[0], run[2]], expect: { duplicateSlots: [], gaps: [{ from: 2, to: 2, unexplained: { paid: 250000 } }], unexplainedSteps: [], malformed: [], completeUpTo: 1, beyondEvent: [], complete: null } },
  { case: 'slot 2 held twice', envelopes: [run[0], run[1], slot(2, 1000, 121000), run[2]], expect: { duplicateSlots: [2], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 3, beyondEvent: [], complete: null } },
  { case: 'a total that does not step by its record\'s value', envelopes: [run[0], slot(2, AMOUNTS[1], 370005), run[2]], expect: {
    duplicateSlots: [], gaps: [], malformed: [], completeUpTo: 3, beyondEvent: [], complete: null,
    unexplainedSteps: [{ slot: 2, cap: 'paid', expected: 370000, actual: 370005 }, { slot: 3, cap: 'paid', expected: 575005, actual: 575000 }],
  } },
  { case: 'slots 41 to 43 only: slots 1 to 40 missing, 5,110,000 unexplained', envelopes: [slot(41, 120000, 5230000), slot(42, 350000, 5580000), slot(43, 205000, 5785000)], expect: {
    duplicateSlots: [], gaps: [{ from: 1, to: 40, unexplained: { paid: 5110000 } }], unexplainedSteps: [], malformed: [], completeUpTo: 0, beyondEvent: [], complete: null,
  } },
  { case: 'complete against the revocation\'s event body', envelopes: run, lastEvent: eventOf(3, 575000), expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 3, beyondEvent: [], complete: true } },
  { case: 'the event body accounts for a slot that is missing', envelopes: run, lastEvent: eventOf(4, 700000), expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 3, beyondEvent: [], complete: false } },
  { case: 'the event body\'s totals differ from the last slot\'s', envelopes: run, lastEvent: eventOf(3, 575001), expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 3, beyondEvent: [], complete: false } },
  { case: 'a record above the event body\'s used (captured after the mandate closed)', envelopes: [...run, slot(4, 1000, 576000)], lastEvent: eventOf(3, 575000), expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 4, beyondEvent: [4], complete: false } },
  { case: 'an event body at used 0 with no record', envelopes: [], lastEvent: eventOf(0, 0), expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [], completeUpTo: 0, beyondEvent: [], complete: true } },
  { case: 'a record whose value at the cap path is not an integer', envelopes: [run[0], slot(2, '250000', 370000)], expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [{ index: 1, reason: 'mandate_totals_malformed' }], completeUpTo: 1, beyondEvent: [], complete: null } },
  { case: 'a record whose slot is not an integer of at least 1', envelopes: [run[0], slot(0, 1000, 121000)], expect: { duplicateSlots: [], gaps: [], unexplainedSteps: [], malformed: [{ index: 1, reason: 'mandate_seq_malformed' }], completeUpTo: 1, beyondEvent: [], complete: null } },
];
for (const c of consumption) {
  agree(`consumption "${c.case}"`, checkMandateConsumption(W4_DOCUMENT, c.envelopes, c.lastEvent ? { lastEvent: c.lastEvent } : {}), c.expect);
}

// ── issuance ────────────────────────────────────────────────────────────

const issuancePayload = (o: Record<string, unknown> = {}) =>
  payload({
    evidenceId: '7a2c0d4e-1111-4a1a-8a1a-000000000001',
    aiSystemId: 'tzun:mandate',
    action: 'issue-mandate',
    aiOutput: { assertionDigest: W4_ASSERTION_DIGEST, mandateDigest: W4_MANDATE_DIGEST, statementDigest: W4_STATEMENT_DIGEST },
    reason: 'Claims-triage mandate for Q4 2026',
    capturedAt: '2026-09-30T14:05:30.000Z',
    decider: human('acct:user-2c9d'),
    ...o,
  });
const otherStatement = { ...W4_STATEMENT, signer: 'user-9999' };
const otherStatementDigest = sha256Hex(canonicalSerializeValue(otherStatement));
const issuanceRow = (link?: string) =>
  link === undefined ? { outcome: 'checked-correct', valid: true } : { outcome: 'checked-wrong', valid: false, reason: 'issuance_material_mismatch', link };
const issuance = [
  { case: 'W4\'s issuance record (W5)', envelope: envelope(issuancePayload(), { mandateIssuance: W4_BLOCK }), expect: issuanceRow() },
  { case: 'the document altered after signing', envelope: envelope(issuancePayload(), { mandateIssuance: { ...W4_BLOCK, document: doc((d) => { at(d, ['limits']).maxRecords = 20000; }) } }), expect: issuanceRow('document') },
  { case: 'aiOutput naming another mandate digest', envelope: envelope(issuancePayload({ aiOutput: { assertionDigest: W4_ASSERTION_DIGEST, mandateDigest: digestOf('x'), statementDigest: W4_STATEMENT_DIGEST } }), { mandateIssuance: W4_BLOCK }), expect: issuanceRow('document') },
  { case: 'a malformed document', envelope: envelope(issuancePayload(), { mandateIssuance: { ...W4_BLOCK, document: { v: 'tzun-mandate/1' } } }), expect: issuanceRow('document') },
  { case: 'aiOutput naming another statement digest', envelope: envelope(issuancePayload({ aiOutput: { assertionDigest: W4_ASSERTION_DIGEST, mandateDigest: W4_MANDATE_DIGEST, statementDigest: digestOf('y') } }), { mandateIssuance: W4_BLOCK }), expect: issuanceRow('statement') },
  {
    case: 'a statement whose signer is not the document\'s principal',
    envelope: envelope(issuancePayload({ aiOutput: { assertionDigest: W4_ASSERTION_DIGEST, mandateDigest: W4_MANDATE_DIGEST, statementDigest: otherStatementDigest } }), { mandateIssuance: { ...W4_BLOCK, statement: otherStatement } }),
    expect: issuanceRow('signer'),
  },
  { case: 'an assertion presenting another challenge', envelope: envelope(issuancePayload(), { mandateIssuance: { ...W4_BLOCK, assertion: assertionPresenting('AAAA') } }), expect: issuanceRow('challenge') },
  { case: 'aiOutput naming another assertion digest', envelope: envelope(issuancePayload({ aiOutput: { assertionDigest: digestOf('z'), mandateDigest: W4_MANDATE_DIGEST, statementDigest: W4_STATEMENT_DIGEST } }), { mandateIssuance: W4_BLOCK }), expect: issuanceRow('assertion') },
  { case: 'a decider that is not the principal', envelope: envelope(issuancePayload({ decider: human('acct:u-4821') }), { mandateIssuance: W4_BLOCK }), expect: issuanceRow('decider') },
  { case: 'an issuance record without its material', envelope: envelope(issuancePayload()), expect: { outcome: 'checked-wrong', valid: false, reason: 'issuance_material_stripped' } },
  { case: 'issuance material on a record that is not an issuance record', envelope: envelope(payload(), { mandateIssuance: W4_BLOCK }), expect: { outcome: 'checked-wrong', valid: false, reason: 'issuance_not_expected' } },
  { case: 'a revocation record (not reported)', envelope: envelope(issuancePayload({ action: 'revoke-mandate' })), expect: null },
  { case: 'an ordinary record (not reported)', envelope: envelope(payload()), expect: null },
];
for (const i of issuance) agree(`issuance "${i.case}"`, checkMandateIssuance(i.envelope), i.expect);
agree('W5 digest', recordDigest(issuance[0].envelope.payload), 'fb29b130c25c42d6ac72f1ea4123f0c542d6fefed9cfcaaa6b9a1b5e74af9844');

// ── event bodies ────────────────────────────────────────────────────────

const W5_DIGEST = 'fb29b130c25c42d6ac72f1ea4123f0c542d6fefed9cfcaaa6b9a1b5e74af9844';
const body = (o: Record<string, unknown>) => ({ v: 'tzun-mandate-event/1', event: 'issued', mandateDigest: W4_MANDATE_DIGEST, record: W5_DIGEST, successor: null, used: null, totals: null, ...o });
const eventBodies = [
  { case: 'W5\'s issued event', body: body({}), wellFormed: true },
  { case: 'revoked, with the values at the revocation', body: body({ event: 'revoked', record: digestOf('revocation record'), used: 43, totals: { paid: 5785000 } }), wellFormed: true },
  { case: 'superseded, naming the successor', body: body({ event: 'superseded', record: digestOf('successor issuance'), successor: digestOf('successor mandate'), used: 43, totals: { paid: 5785000 } }), wellFormed: true },
  { case: 'expired, its record the issuance record', body: body({ event: 'expired', used: 43, totals: { paid: 5785000 } }), wellFormed: true },
  { case: 'expired with no cap (totals null)', body: body({ event: 'expired', used: 0 }), wellFormed: true },
  { case: 'an event outside the four', body: body({ event: 'paused' }), wellFormed: false },
  { case: 'a negative used', body: body({ event: 'revoked', used: -1 }), wellFormed: false },
  { case: 'totals {} (write null)', body: body({ event: 'revoked', used: 1, totals: {} }), wellFormed: false },
  { case: 'a total that is a string', body: body({ event: 'revoked', used: 1, totals: { paid: '5' } }), wellFormed: false },
  { case: 'a prefixed record digest', body: body({ record: `sha256:${W5_DIGEST}` }), wellFormed: false },
  { case: 'a member outside the seven', body: { ...body({}), at: '2026-10-01T00:00:00.000Z' }, wellFormed: false },
].map((e) => {
  const canonical = e.wellFormed ? canonicalSerializeValue(e.body) : null;
  return { ...e, digest: canonical === null ? null : sha256Hex(canonical) };
});
agree('W5 event digest', eventBodies[0].digest, '82511c5907fe6cc93c23b40b0933d4576ea86af28700eddbadae0856ece9b7b3');
for (const e of eventBodies) agree(`eventBodies "${e.case}" digest`, mandateEventBodyDigest(e.body), e.digest);
const eventWriterRefusals = [
  { case: 'an issued event naming a successor', parts: { event: 'issued', mandateDigest: W4_MANDATE_DIGEST, record: W5_DIGEST, successor: digestOf('s') } },
  { case: 'a superseded event naming no successor', parts: { event: 'superseded', mandateDigest: W4_MANDATE_DIGEST, record: W5_DIGEST, used: 3 } },
  { case: 'an issued event with used', parts: { event: 'issued', mandateDigest: W4_MANDATE_DIGEST, record: W5_DIGEST, used: 0 } },
  { case: 'a revoked event without used', parts: { event: 'revoked', mandateDigest: W4_MANDATE_DIGEST, record: W5_DIGEST } },
];
for (const r of eventWriterRefusals) {
  let threw = false;
  try {
    buildMandateEventBody(r.parts as never);
  } catch {
    threw = true;
  }
  agree(`eventWriterRefusals "${r.case}"`, threw, true);
}

// ── claims ──────────────────────────────────────────────────────────────

const ISSUANCE_TARGET = { digest: W5_DIGEST, evidenceId: '7a2c0d4e-1111-4a1a-8a1a-000000000001', locator: { origin: CLAIMS_ORIGIN, seq: 1 } };
const MANDATE_LINK = { rel: 'mandate', target: ISSUANCE_TARGET, attrs: null };
const claimPayload = (o: Record<string, unknown> = {}) => {
  const p = mandated(o);
  delete p.signoffExpectation;
  return { ...p, links: o.links ?? null };
};
const capDoc = doc((d) => {
  at(d, ['limits']).cumulative = { paid: { path: '/aiOutput/paidMinor', max: 250000000 } };
});
const open = (used: number, paid: number | null) => ({ state: 'open', used, totals: paid === null ? null : { paid } });
const refusal = (code: string, field: string, extra: Record<string, unknown> = {}) => ({ ok: false, code, field, ...extra });
const claims = [
  {
    case: 'W6: slot 41, the total 5,110,000 + 120,000, no confirmation owed; the mandate link added',
    document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload(),
    expect: { ok: true, expectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm: false }, links: [MANDATE_LINK], expectUsed: 40, caps: [{ cap: 'paid', expectTotal: 5110000, newTotal: 5230000 }], confirmHolding: [] },
  },
  {
    case: 'a fraud-flagged claim: a confirmation is owed',
    document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ aiOutput: { ...CLAIM_OUTPUT, fraudFlag: true } }),
    expect: { ok: true, expectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm: true }, links: [MANDATE_LINK], expectUsed: 40, caps: [{ cap: 'paid', expectTotal: 5110000, newTotal: 5230000 }], confirmHolding: ['fraud'] },
  },
  {
    case: 'the first claim (no totals yet)',
    document: W4_DOCUMENT, mandate: open(0, null), payload: claimPayload(),
    expect: { ok: true, expectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 1, totals: { paid: 120000 }, confirm: false }, links: [MANDATE_LINK], expectUsed: 0, caps: [{ cap: 'paid', expectTotal: 0, newTotal: 120000 }], confirmHolding: [] },
  },
  {
    case: 'the record\'s own links kept beside the mandate link, sorted',
    document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ links: [{ rel: 'derivedFrom', target: { digest: digestOf('claim intake'), evidenceId: null, locator: null }, attrs: null }] }),
    expect: {
      ok: true, expectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm: false },
      links: [{ rel: 'derivedFrom', target: { digest: digestOf('claim intake'), evidenceId: null, locator: null }, attrs: null }, MANDATE_LINK],
      expectUsed: 40, caps: [{ cap: 'paid', expectTotal: 5110000, newTotal: 5230000 }], confirmHolding: [],
    },
  },
  { case: 'a decider of kind agent (a decision under a mandate is agent-mandated)', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ decider: agentDecider('agent') }), expect: refusal('agent_not_in_mandate', 'decider.kind') },
  { case: 'a decider that is not one of the agents', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ decider: agentDecider('agent-mandated', AGENT_B) }), expect: refusal('agent_not_in_mandate', 'decider') },
  { case: 'a revoked mandate', document: W4_DOCUMENT, mandate: { ...open(43, 5785000), state: 'revoked' }, payload: claimPayload(), expect: refusal('mandate_not_open', 'mandate') },
  { case: 'a claim after the validity window: refused, and the mandate is now expired', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ capturedAt: '2027-01-01T00:00:00.000Z' }), expect: refusal('outside_validity', 'capturedAt', { expired: true }) },
  { case: 'a claim before the validity window', document: W4_DOCUMENT, mandate: open(0, null), payload: claimPayload({ capturedAt: '2026-09-30T23:59:59.999Z' }), expect: refusal('outside_validity', 'capturedAt') },
  { case: 'a claim at the last millisecond of the window', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ capturedAt: '2026-12-31T23:59:59.999Z' }), expect: {
    ok: true, expectation: { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 41, totals: { paid: 5230000 }, confirm: false }, links: [MANDATE_LINK], expectUsed: 40, caps: [{ cap: 'paid', expectTotal: 5110000, newTotal: 5230000 }], confirmHolding: [],
  } },
  { case: 'a record of another schema version', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ schemaVersion: 'v9.9' }), expect: refusal('schema_version_mismatch', 'schemaVersion') },
  { case: 'an action outside the scope', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ action: 'deny' }), expect: refusal('outside_scope', 'payload', { findings: [{ constraint: 'actions' }] }) },
  { case: 'an amount over the per-decision cap', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ aiOutput: { ...CLAIM_OUTPUT, amountMinor: 600000 } }), expect: refusal('outside_scope', 'payload', { findings: [{ constraint: 'predicate', name: 'cap' }] }) },
  { case: 'the amount missing', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ aiOutput: { fraudFlag: false, recommendation: 'approve' } }), expect: refusal('scope_undeterminable', 'payload', { findings: [{ constraint: 'predicate', name: 'cap' }] }) },
  { case: 'the fraud flag missing: whether a confirmation is owed cannot be determined', document: W4_DOCUMENT, mandate: open(40, 5110000), payload: claimPayload({ aiOutput: { amountMinor: 120000, recommendation: 'approve' } }), expect: refusal('confirm_undeterminable', 'confirm', { findings: [{ constraint: 'confirm', name: 'fraud' }] }) },
  { case: 'the value at a cap path that is not an integer', document: capDoc, mandate: open(40, 5110000), payload: claimPayload({ aiOutput: { ...CLAIM_OUTPUT, paidMinor: '120000' } }), expect: refusal('cap_value_invalid', 'limits.cumulative.paid') },
  { case: 'every slot used', document: W4_DOCUMENT, mandate: open(10000, 5110000), payload: claimPayload(), expect: refusal('mandate_full', 'mandate') },
  { case: 'a claim that would take the cap past its maximum', document: W4_DOCUMENT, mandate: open(40, 249950000), payload: claimPayload(), expect: refusal('cap_exceeded', 'limits.cumulative.paid') },
];
for (const c of claims) {
  const got = planMandateClaim({ document: c.document, mandate: c.mandate as never, payload: c.payload, assertionDigest: W4_ASSERTION_DIGEST, issuance: ISSUANCE_TARGET });
  const { message: _message, ...rest } = got as Record<string, unknown>;
  agree(`claims "${c.case}"`, rest, c.expect);
}

// ── lifecycle ───────────────────────────────────────────────────────────

const lifecycle = {
  revocationInstants: [
    { case: 'the instant the revocation is captured', claimedRevocationInstant: '2026-11-21T09:00:00.000Z', capturedAt: '2026-11-21T09:00:00.000Z', refused: false },
    { case: 'an earlier instant (recorded as claimed)', claimedRevocationInstant: '2026-11-01T00:00:00.000Z', capturedAt: '2026-11-21T09:00:00.000Z', refused: false },
    { case: 'a future instant', claimedRevocationInstant: '2026-11-21T09:00:00.001Z', capturedAt: '2026-11-21T09:00:00.000Z', refused: true },
    { case: 'an instant without milliseconds', claimedRevocationInstant: '2026-11-01T00:00:00Z', capturedAt: '2026-11-21T09:00:00.000Z', refused: true },
    { case: 'an instant with an offset', claimedRevocationInstant: '2026-11-01T00:00:00.000+01:00', capturedAt: '2026-11-21T09:00:00.000Z', refused: true },
  ],
  successors: [
    { case: 'the same principal, naming its predecessor', document: doc((d) => { d.predecessor = W4_MANDATE_DIGEST; d.mandateId = '6b1f0e2a-7c3d-4e5f-8a9b-0c1d2e3f4a5c'; }), predecessor: W4_DOCUMENT, refused: false },
    { case: 'another principal (a new principal revokes and issues afresh)', document: doc((d) => { d.predecessor = W4_MANDATE_DIGEST; at(d, ['principal']).signer = 'user-77aa'; }), predecessor: W4_DOCUMENT, refused: true },
    { case: 'naming another predecessor digest', document: doc((d) => { d.predecessor = digestOf('another mandate'); }), predecessor: W4_DOCUMENT, refused: true },
  ],
  confirmations: [
    { case: 'confirm true, not yet confirmed', envelope: envelope(mandated({}, { confirm: true })), refused: null },
    { case: 'confirm false: no confirmation is owed', envelope: envelope(mandated()), refused: 'confirmation_not_owed' },
    { case: 'confirm true, already confirmed (filled once)', envelope: envelope(mandated({}, { confirm: true }), (d) => ({ confirmation: assertionPresenting(createHash('sha256').update('tzun-confirm-v1' + d).digest('base64url')) })), refused: 'already_confirmed' },
    { case: 'a record that is not under a mandate', envelope: envelope(payload({ signoffExpectation: { policyDigest: digestOf('p') } })), refused: 'confirmation_not_owed' },
  ],
  expiry: [
    { case: 'after notAfter', notAfter: '2026-12-31T23:59:59.999Z', instant: '2027-01-01T00:00:00.000Z', expired: true },
    { case: 'at notAfter', notAfter: '2026-12-31T23:59:59.999Z', instant: '2026-12-31T23:59:59.999Z', expired: false },
    { case: 'no notAfter', notAfter: null, instant: '2099-01-01T00:00:00.000Z', expired: false },
  ],
};
for (const r of lifecycle.revocationInstants) agree(`revocation "${r.case}"`, revocationInstantViolation(r.claimedRevocationInstant, r.capturedAt) !== null, r.refused);
for (const s of lifecycle.successors) agree(`successor "${s.case}"`, predecessorPrincipalViolation(s.document as unknown as MandateDocument, s.predecessor) !== null, s.refused);
for (const c of lifecycle.confirmations) agree(`confirmation "${c.case}"`, mandateConfirmationViolation(c.envelope)?.code ?? null, c.refused);
for (const e of lifecycle.expiry) agree(`expiry "${e.case}"`, mandateExpiredAt(e.notAfter, e.instant), e.expired);

emit({
  description:
    'Mandates (Record §9.6 to §9.10): the document tzun-mandate/1, the statement tzun-signoff-mandate/1 without a printed name, the ' +
    'assertion digest, predicates, scope, single-record limits, consumption over a set of records, the issuance row (Verification ' +
    '§4.12), event bodies and their digests, the claim a capture under a mandate makes, and the lifecycle refusals.',
  source:
    'Generated by scripts/generate-mandate-vectors.ts. Every expected answer is written in the script from the specification, and the ' +
    'script stops if the engine disagrees with one. W4\'s assertion is a real Ed25519 signature by the RFC 8037 Appendix A key; every other ' +
    'signature is a placeholder or a constructed ES256 encoding: the checks here read encodings and challenges, never whether a ' +
    'signature verifies. A predicates case with payloadJson is parsed by the implementation\'s own JSON reader, because the spelling ' +
    'of its number is the point.',
  documents,
  statements,
  assertionDigests,
  predicates,
  scope,
  limits,
  consumption,
  issuance,
  eventBodies,
  eventWriterRefusals,
  claims,
  lifecycle,
});
