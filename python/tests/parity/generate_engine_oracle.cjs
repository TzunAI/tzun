// Runs every case of oracle_cases.py through the built engine and prints the
// cases with the engine's answers, one JSON document. See oracle_cases.py.
//
//   node python/tests/parity/generate_engine_oracle.cjs <cases.json>
'use strict';
const fs = require('fs');
const path = require('path');
const e = require(path.resolve(__dirname, '../../../packages/engine/dist/index.js'));

const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const W6_MANDATE_LINK_TARGET = {
  digest: 'fb29b130c25c42d6ac72f1ea4123f0c542d6fefed9cfcaaa6b9a1b5e74af9844',
  evidenceId: '7a2c0d4e-1111-4a1a-8a1a-000000000001',
  locator: { origin: 'test.insurer.example/9a8b7c6d5e4f30211203f4e5d6c7b8a9/evidence/636c61696d73', seq: 1 },
};

function thrown(err) {
  const out = { name: err.name };
  for (const k of ['code', 'field', 'step', 'link', 'rule']) if (err[k] !== undefined) out[k] = err[k];
  return out;
}

function attempt(fn) {
  try {
    return { ok: fn() };
  } catch (err) {
    return { error: thrown(err) };
  }
}

const RUN = {
  payloadRows(payload, systemRecord, env) {
    const p = payload && typeof payload === 'object' ? payload : {};
    return {
      gate: e.payloadRecordRuleViolation(payload, systemRecord ? { systemRecord } : {}),
      decider: e.deciderViolation(p.decider),
      contributions: e.contributionsViolation(p.contributions, { decider: p.decider, action: p.action, reason: p.reason }),
      links: e.linksViolation(p.links, p),
      linkRecord: e.linkRecordViolation(payload),
      checkDecider: e.checkDecider(env),
      checkContributions: e.checkContributions(payload),
      checkLinks: e.checkLinks(payload),
      unhashed: e.unhashedPayloadMembers(payload),
      generation: e.recordFieldSetGeneration(env),
      earlier: e.earlierFieldSet(payload, env.integrity.canonicalDigest),
    };
  },
  envelopeRows(env) {
    const v = e.verifyEnvelope(env);
    return {
      expectation: e.checkSignoffExpectation(env),
      issuance: e.checkMandateIssuance(env),
      verify: {
        digest: v.recomputedDigest === v.storedDigest,
        signoffExpectationValid: v.signoffExpectationValid,
        signoffExpectationReason: v.signoffExpectationReason ?? null,
        decider: v.decider,
        contributions: v.contributions,
        links: v.links,
        mandate: v.mandate ?? null,
        unhashedPayloadMembers: v.unhashedPayloadMembers,
        fieldSet: v.fieldSet ?? null,
      },
    };
  },
  documentRows(doc, payload) {
    return {
      prepare: e.mandateDocumentViolation(doc),
      reader: e.mandateDocumentViolation(doc, { prepare: false }),
      digest: e.mandateDigest(doc),
      scope: e.evaluateMandateScope(doc, payload),
      limits: e.checkMandateLimits(doc, payload),
      confirm: e.evaluateMandateConfirm(doc, payload),
      caps: e.mandateCapValues(doc, payload),
      plan: e.planMandateClaim({
        document: doc,
        mandate: { state: 'open', used: 40, totals: { paid: 5000000 } },
        payload: { ...payload, signoffExpectation: null, links: null },
        assertionDigest: '79aafeb32c197be65d3b27c7b1cc469beff89e8650d1a84e02b437ec7937966d',
        issuance: W6_MANDATE_LINK_TARGET,
      }),
    };
  },
  evaluatePredicate: (p, payload) => e.evaluatePredicate(p, payload),
  globMatch: (p, s) => e.globMatch(p, s),
  agentRows(d) {
    const violation = e.agentDescriptorViolation(d);
    return {
      violation,
      reader: e.agentDescriptorViolation(d, { limits: false }),
      digest: e.agentDescriptorViolation(d, { limits: false }) === null ? e.agentDescriptorDigest(d) : null,
    };
  },
  assertionDigestResult: (a) => e.assertionDigestResult(a),
  parseFreshnessReference: (r) => e.parseFreshnessReference(r),
  isEvidenceLogOrigin: (o) => e.isEvidenceLogOrigin(o),
  signoffExpectationViolation: (v) => e.signoffExpectationViolation(v),
  revocationInstantViolation: (x, at) => e.revocationInstantViolation(x, at),
  mandateExpiredAt: (a, b) => e.mandateExpiredAt(a, b),
  buildContributions: (input, ctx) => attempt(() => e.buildContributions(input, ctx)),
  buildLinks: (inputs, options) => attempt(() => e.buildLinks(inputs, options)),
};

const out = cases.map((c) => {
  const run = RUN[c.fn];
  if (!run) throw new Error(`no runner for ${c.fn}`);
  return { ...c, expect: run(...c.args) };
});
process.stdout.write(JSON.stringify(out));
