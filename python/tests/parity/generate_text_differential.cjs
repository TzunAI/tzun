// Parses every text of text_differential_cases.py with JSON.parse, runs the
// built engine on it and prints the cases with the engine's answers, one JSON
// document. See text_differential_cases.py.
//
//   node python/tests/parity/generate_text_differential.cjs <cases.json>
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const e = require(path.resolve(__dirname, '../../../packages/engine/dist/index.js'));

const items = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const FIELDS = [...e.V1_0_HASHED_FIELDS];
const ZERO = '0'.repeat(64);

function canon(payload) {
  try {
    return { ok: e.canonicalSerialize(payload, FIELDS) };
  } catch (err) {
    return { error: err.name };
  }
}
const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
function pick(v, keys) {
  if (v === null || v === undefined) return null;
  const o = {};
  for (const k of keys) if (v[k] !== undefined && v[k] !== null) o[k] = v[k];
  return o;
}
function rows(v) {
  return {
    holds: v.recomputedDigest === v.storedDigest,
    signoffExpectationValid: v.signoffExpectationValid ?? null,
    signoffExpectationReason: v.signoffExpectationReason ?? null,
    decider: v.decider ?? null,
    contributions: v.contributions ?? null,
    links: v.links ?? null,
    mandate: v.mandate ?? null,
  };
}

const out = items.map((it) => {
  if (it.kind === 'payload') {
    const p = JSON.parse(it.text);
    const c = canon(p);
    const digest = c.ok !== undefined ? sha(c.ok) : null;
    const env = {
      envelopeVersion: 'e1',
      payload: p,
      integrity: { canonicalDigest: digest ?? ZERO, chainLink: null },
      nonRepudiation: {},
      custodyChain: [],
      attestationStatus: 'none',
    };
    const v = e.verifyEnvelope(env);
    return {
      ...it,
      ts: {
        canonical: c.ok !== undefined ? c : { error: true },
        digest,
        gate: pick(e.payloadRecordRuleViolation(p, it.systemRecord ? { systemRecord: it.systemRecord } : {}), ['rule', 'code', 'field']),
        verify: { ...rows(v), unhashedPayloadMembers: v.unhashedPayloadMembers ?? null },
      },
    };
  }
  const probe = JSON.parse(it.text.replace('"__DIGEST__"', JSON.stringify(ZERO)));
  const c = canon(probe.payload);
  const digest = c.ok !== undefined ? sha(c.ok) : ZERO;
  const text = it.text.replace('"__DIGEST__"', JSON.stringify(digest));
  const env = JSON.parse(text);
  return {
    ...it,
    text,
    ts: {
      canonical: c.ok !== undefined ? c : { error: true },
      digest,
      expectation: e.checkSignoffExpectation(env),
      issuance: e.checkMandateIssuance(env),
      verify: rows(e.verifyEnvelope(env)),
    },
  };
});
process.stdout.write(JSON.stringify(out));
