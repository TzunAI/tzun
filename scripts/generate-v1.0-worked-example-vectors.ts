/**
 * Generate vectors/v1.0-worked-example-vectors.json: the worked examples W1 to
 * W7 of the v1.0 record as revised in place in 0.8.0 (the examples of Record
 * §4.4, §6.9, §8.6, §9.6 and §9.7), and the sub-vectors they rest on, each
 * with its canonical bytes and its digest:
 *
 *   - records             W1 (an agent's own decision, a contributions list of
 *                         one), W1r (W1 relabelled to a human decider: a
 *                         tamper), W2 (a human decision on a direct model
 *                         call, the step's actor null), W3 (two models and a
 *                         human decide step, deriving from W2), W3s (W3 with
 *                         its amount swapped after the review, re-hashed), W5
 *                         (W4's issuance record), W6 (a record under W4's
 *                         mandate, slot 41), W7 (a link record: a complaint in
 *                         another store appeals W3);
 *   - outputDigests       W1's and W3's step outputs and W3's swapped proposal;
 *   - stepDigests         W1's step and W3's three steps;
 *   - agentDescriptors    the example descriptor (729 bytes), the same with its
 *                         sets supplied out of order, and a set holding a
 *                         non-ASCII member (sorted by UTF-8 bytes);
 *   - deciderCommitments  the example commitment, three more, and one whose
 *                         salt is derived from a store secret and an
 *                         idempotency key;
 *   - mandateDocuments    W4's document (921 bytes);
 *   - mandateStatements   W4's statement (no signerName) and its challenge;
 *   - mandateAssertions   W4's Ed25519 assertion, signed with the RFC 8037
 *                         Appendix A key over the challenge;
 *   - mandateEventBodies  W5's issued event, and one of each other kind, each
 *                         with its canonical bytes and its digest;
 *   - confirmationChallenges  the confirmation challenge of W6's digest;
 *   - assertionDigests    one ES256 signature as low-S, high-S, non-minimal
 *                         and long-length DER (one digest), an Ed25519
 *                         signature, and two signatures that are not DER (no
 *                         digest).
 *
 *   pnpm exec tsx scripts/generate-v1.0-worked-example-vectors.ts > vectors/v1.0-worked-example-vectors.json
 *
 * Every record is built by the engine's own builders (buildContributions,
 * singleModel, buildLinks, mandateIssuanceInput, planMandateClaim,
 * assembleEnvelope); every expected value is recomputed here with node:crypto
 * alone, and the specification's published digests are written here as constants.
 * The script stops if any of the three disagree. The TS suite
 * (tests/ts/v1.0-worked-example-vectors.test.ts) and the Python recomputation
 * (tests/cross-sdk/test_v1_0_worked_example_vectors.py) hold both languages
 * to the file.
 */
import { createHash, createHmac, createPrivateKey, sign } from 'node:crypto';
import {
  P256_ORDER,
  V1_0_HASHED_FIELDS,
  agentDescriptorDigest,
  assembleEnvelope,
  assertionDigest,
  buildContributions,
  buildLinks,
  buildMandateEventBody,
  canonicalSerialize,
  canonicalSerializeAgentDescriptor,
  canonicalSerializeValue,
  deciderCommitment,
  deciderCommitmentSalt,
  mandateConfirmationChallenge,
  mandateDigest,
  mandateEventBodyDigest,
  mandateIssuanceInput,
  mandateStatementChallenge,
  mandateStatementDigest,
  outputDigest,
  planMandateClaim,
  singleModel,
  stepDigest,
  type AgentDescriptor,
  type AiBom,
  type EnvelopeInput,
  type EvidenceEnvelope,
  type MandateDocument,
  type MandateStatement,
  type WebauthnAssertion,
} from '@tzun/engine';

const FIELDS = [...V1_0_HASHED_FIELDS];
const sha256Hex = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
const prefixed = (value: unknown) => 'sha256:' + sha256Hex(canonicalSerializeValue(value));

function stop(message: string): never {
  process.stderr.write(`generate-v1.0-worked-example-vectors: ${message}\n`);
  process.exit(1);
}
function agree(label: string, engine: unknown, expected: unknown): void {
  if (JSON.stringify(engine) !== JSON.stringify(expected)) {
    stop(`${label}: the engine says ${JSON.stringify(engine)}, the rule says ${JSON.stringify(expected)}`);
  }
}

const AGENT = 'sha256:eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f';
const MODEL = 'sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947';
const LENDER_ORIGIN = 'test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/6c656e64696e67';
const CLAIMS_ORIGIN = 'test.insurer.example/9a8b7c6d5e4f30211203f4e5d6c7b8a9/evidence/636c61696d73';
type Ip = NonNullable<AiBom['inferenceParameters']>;
const bom = (md: string, ip: Ip | null = null): AiBom => ({
  modelDescriptorDigest: md, vendorFingerprint: null, promptTemplate: null, inferenceParameters: ip, infrastructure: null,
});
const human = (id: string) => ({ kind: 'human' as const, id, agent: null, credential: null, freshness: null });
const heldOf = (env: EvidenceEnvelope, origin: string) => ({
  payload: env.payload as unknown as Record<string, unknown>,
  digest: env.integrity.canonicalDigest,
  origin,
});

function recordCase(id: string, label: string, payload: unknown, expected: { bytes: number; digest: string }) {
  const canonical = canonicalSerialize(payload as Record<string, unknown>, FIELDS);
  const digest = sha256Hex(canonical);
  agree(`${id} byte length`, Buffer.byteLength(canonical), expected.bytes);
  agree(`${id} digest`, digest, expected.digest);
  return { id, label, payload, canonical, byteLength: Buffer.byteLength(canonical), digest };
}

// ── W1: an agent's own decision, a contributions list of one ─────────────
const w1Output = { amount: 1250, recommendation: 'pay' };
const w1Decider = {
  kind: 'agent' as const,
  id: `desc:${AGENT}`,
  agent: AGENT,
  credential: 'e0d80c85a2b54cb68567fc4f7a56f20f321839af3d8f888df8b90b0a6920b386',
  freshness: 'eip155:1@9123456:0x8ae3e2d5ddeee120de1e2e58f78ed0ed9c7b7ead28098938757d597d09c3f64c',
};
const w1Input: EnvelopeInput = {
  aiSystemId: 'claims-model',
  aiOutput: w1Output,
  action: 'pay',
  reason: 'Amount below the automatic-payment limit; documents complete',
  decider: w1Decider,
};
w1Input.contributions = buildContributions(singleModel(bom(MODEL), { actor: { kind: 'agent', agent: AGENT } }), {
  decider: w1Decider, action: w1Input.action, reason: w1Input.reason, aiOutput: w1Output,
});
const w1 = assembleEnvelope(w1Input, { evidenceId: '5f0c1f0e-2222-4b2b-9b2b-000000000041', sequenceNumber: 41, capturedAt: '2026-09-30T14:03:11.000Z' });
const w1r = { ...w1.payload, decider: { ...w1.payload.decider!, kind: 'human' as const, id: 'acct:u-4821', agent: null } };

// ── W2: a human decision on a direct model call ──────────────────────────
const w2Output = { missingDocuments: 0, route: 'underwriting' };
const w2Input: EnvelopeInput = {
  aiSystemId: 'intake-model', aiOutput: w2Output, action: 'route', reason: 'Application complete; route to underwriting', decider: human('acct:u-4821'),
};
w2Input.contributions = buildContributions(
  singleModel(bom('sha256:' + '0c'.repeat(32), { temperature: 0, topP: null, maxTokens: 400, seed: null, stopSequences: null })),
  { decider: w2Input.decider, action: w2Input.action, reason: w2Input.reason, aiOutput: w2Output },
);
const w2 = assembleEnvelope(w2Input, { evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000006', sequenceNumber: 6, capturedAt: '2026-10-05T15:01:00.000Z' });

// ── W3: two models and a human, deriving from W2 ─────────────────────────
const A1 = 'sha256:' + 'a1'.repeat(32);
const B2 = 'sha256:' + 'b2'.repeat(32);
const ip800: Ip = { temperature: 0, topP: null, maxTokens: 800, seed: null, stopSequences: null };
const w3Output = { maxApprovedAmount: 25000, recommendation: 'approve', riskScore: 31 };
const reviewOutput = { factors: ['debtToIncome', 'incomeStability'], verdict: 'approve' };
const w3Action = 'approve';
const w3Reason = 'Income verified; reviewer found no fair-lending concerns';
const w3Decider = human('acct:u-4821');
const proposal = outputDigest(w3Output);
const review = outputDigest(reviewOutput);
const w3Contributions = buildContributions(
  {
    steps: [
      { role: 'propose:underwriting', actor: { kind: 'agent', agent: A1 }, aiBom: bom('sha256:' + '0a'.repeat(32), ip800), inputs: [`sha256:${w2.integrity.canonicalDigest}`] },
      {
        role: 'review:fair-lending', actor: { kind: 'agent', agent: B2 }, aiBom: bom('sha256:' + '0b'.repeat(32), ip800),
        inputs: [proposal], outputOf: reviewOutput, verdict: 'approve', reason: 'No protected-class proxies in the factors',
      },
      { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null }, inputs: [proposal, review], verdict: 'approve' },
    ],
  },
  { decider: w3Decider, action: w3Action, reason: w3Reason, aiOutput: w3Output },
);
const w3Links = buildLinks([{ rel: 'derivedFrom', target: { evidenceId: w2.payload.evidenceId } }], { held: [heldOf(w2, LENDER_ORIGIN)] });
const w3 = assembleEnvelope(
  { aiSystemId: 'lending-model', aiOutput: w3Output, action: w3Action, reason: w3Reason, decider: w3Decider, contributions: w3Contributions, links: w3Links },
  {
    evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000007', sequenceNumber: 7, capturedAt: '2026-10-05T15:04:05.000Z',
    signoffExpectation: { policyDigest: 'c6f7fb5297c99674b01b72497dafdd6cdbae77553de269ff81dc1adff5873e3a' },
  },
);
const w3s = { ...w3.payload, aiOutput: { ...w3Output, maxApprovedAmount: 45000 } };

// ── W4: the mandate document, statement and assertion ────────────────────
const w4Document: MandateDocument = {
  v: 'tzun-mandate/1',
  mandateId: '6b1f0e2a-7c3d-4e5f-8a9b-0c1d2e3f4a5b',
  principal: { signer: 'user-2c9d', credential: null },
  agents: [`desc:${AGENT}`],
  schemaVersion: 'v1.0',
  scope: {
    aiSystemIds: ['claims-triage-v4'],
    actions: ['approve', 'refer'],
    models: [MODEL],
    predicates: { cap: { op: 'le', path: '/aiOutput/amountMinor', quant: null, value: 500000 } },
  },
  confirm: { fraud: { op: 'eq', path: '/aiOutput/fraudFlag', quant: null, value: true } },
  validity: { notBefore: '2026-10-01T00:00:00.000Z', notAfter: '2026-12-31T23:59:59.999Z' },
  limits: { maxRecords: 10000, cumulative: { paid: { path: '/aiOutput/amountMinor', max: 250000000 } } },
  delegation: { allowed: false, maxDepth: 0, attenuation: 'subset' },
  review: { maxAgeMs: 604800000 },
  policyDigest: null,
  predecessor: null,
  parent: null,
};
const w4MandateDigest = sha256Hex(canonicalSerializeValue(w4Document));
const w4Statement: MandateStatement = {
  v: 'tzun-signoff-mandate/1', mode: 'mandate', mandateDigest: w4MandateDigest, signer: 'user-2c9d', signerKind: 'human',
  meaning: 'responsibility', policyDigest: 'none',
  notBefore: 'eip155:1@23400000:0x9709713cdb609ef086959f42eb4a56159cb9ac637e3f32fb381796e68b2c7efb',
};
const w4StatementDigest = sha256Hex(canonicalSerializeValue(w4Statement));
const w4Challenge = createHash('sha256').update('tzun-signoff-v1' + w4StatementDigest).digest('base64url');
// RFC 8037 Appendix A's Ed25519 key: Ed25519 signs deterministically, so the assertion is reproducible.
const rfc8037 = createPrivateKey({
  key: { kty: 'OKP', crv: 'Ed25519', d: 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' },
  format: 'jwk',
});
const authData = Buffer.concat([createHash('sha256').update('demo.tzun.ai').digest(), Buffer.from([0x05, 0, 0, 0, 1])]);
const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: w4Challenge, origin: 'https://demo.tzun.ai', crossOrigin: false }));
const w4Signature = sign(null, Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), rfc8037);
const w4Assertion: WebauthnAssertion = {
  signature: w4Signature.toString('base64url'),
  credentialKeyId: 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
  algorithm: 'Ed25519',
  authenticatorData: authData.toString('base64url'),
  clientDataJSON: clientData.toString('base64url'),
};
const w4AssertionDigest = createHash('sha256')
  .update('tzun-assertion-v1', 'utf8')
  .update(createHash('sha256').update(authData).digest())
  .update(createHash('sha256').update(clientData).digest())
  .update(createHash('sha256').update(w4Signature).digest())
  .digest('hex');
agree('W4 document bytes', Buffer.byteLength(canonicalSerializeValue(w4Document)), 921);
agree('W4 mandate digest', w4MandateDigest, '26b1fbef903914e39cb45378b7f10648611c751c1b93624173bcfe7b7b9938da');
agree('engine W4 mandate digest', mandateDigest(w4Document), w4MandateDigest);
agree('W4 statement digest', w4StatementDigest, '9a2e761fd633a06433c2e386fd2107112260da481db7c4c4b5795954a7e69492');
agree('engine W4 statement digest', mandateStatementDigest(w4Statement), w4StatementDigest);
agree('W4 challenge', w4Challenge, 'KZTU75Uvu5IeVsZpIpEN1SDqskrp3rA3Dcwl8oMgUBM');
agree('engine W4 challenge', mandateStatementChallenge(w4StatementDigest), w4Challenge);
agree('W4 assertion digest', w4AssertionDigest, '79aafeb32c197be65d3b27c7b1cc469beff89e8650d1a84e02b437ec7937966d');
agree('engine W4 assertion digest', assertionDigest(w4Assertion), w4AssertionDigest);

// ── W5: the issuance record ──────────────────────────────────────────────
const w5Block = { statement: w4Statement, assertion: w4Assertion, assertionTimestamp: null, document: w4Document };
const w5 = assembleEnvelope(
  mandateIssuanceInput({ document: w4Document, statement: w4Statement, assertion: w4Assertion, reason: 'Claims-triage mandate for Q4 2026' }),
  { evidenceId: '7a2c0d4e-1111-4a1a-8a1a-000000000001', sequenceNumber: 1, capturedAt: '2026-09-30T14:05:30.000Z', systemRecord: 'mandate', attestation: { mandateIssuance: w5Block } },
);

// ── W6: a record under W4's mandate, slot 41 ─────────────────────────────
const w6Output = { amountMinor: 120000, fraudFlag: false, recommendation: 'approve' };
const w6Decider = {
  kind: 'agent-mandated' as const, id: `desc:${AGENT}`, agent: AGENT, credential: null,
  freshness: 'eip155:1@23652000:0x' + '5e'.repeat(32),
};
const w6Input: EnvelopeInput = {
  aiSystemId: 'claims-triage-v4', aiOutput: w6Output, action: 'approve', reason: 'Policy active; invoice matches the repair estimate', decider: w6Decider,
};
w6Input.contributions = buildContributions(singleModel(bom(MODEL), { actor: { kind: 'agent-mandated', agent: AGENT } }), {
  decider: w6Decider, action: w6Input.action, reason: w6Input.reason, aiOutput: w6Output,
});
// The mandate link's target: the issuance record W5, resolved in the store.
const [w6MandateLink] = buildLinks([{ rel: 'mandate', target: { evidenceId: w5.payload.evidenceId } }], {
  held: [heldOf(w5, CLAIMS_ORIGIN)], allowReserved: ['mandate'],
});
const w6Plan = planMandateClaim({
  document: w4Document,
  mandate: { state: 'open', used: 40, totals: { paid: 5110000 } },
  payload: { ...w6Input, links: null, schemaVersion: 'v1.0', capturedAt: '2026-11-20T10:14:50.000Z' } as unknown as Record<string, unknown>,
  assertionDigest: w4AssertionDigest,
  issuance: w6MandateLink.target,
});
if (!w6Plan.ok) stop(`W6 claim refused: ${w6Plan.code}`);
w6Input.links = w6Plan.links;
const w6 = assembleEnvelope(w6Input, {
  evidenceId: '7a2c0d4e-2222-4b2b-9b2b-000000000141', sequenceNumber: 141, capturedAt: '2026-11-20T10:14:50.000Z',
  signoffExpectation: w6Plan.expectation, attestation: { mandate: w5Block },
});

// ── W7: a link record ───────────────────────────────────────────────────
const w7 = assembleEnvelope(
  {
    aiSystemId: 'tzun:link', aiOutput: {}, action: 'link', reason: 'Complaint C-1182 contests the underwriting decision', decider: human('acct:u-7702'),
    contributions: null,
    links: buildLinks(
      [
        { rel: 'appeals', target: { evidenceId: w3.payload.evidenceId } },
        { rel: 'subject', target: { digest: 'c0'.repeat(32), external: true } },
      ],
      { held: [heldOf(w3, LENDER_ORIGIN), null], allowReserved: ['subject'], linkRecord: true },
    ),
  },
  { evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000019', sequenceNumber: 19, capturedAt: '2026-10-19T09:30:00.000Z', systemRecord: 'link' },
);

const records = [
  recordCase('W1', "An agent's own decision: its one model's step proposed by the same agent; no decide step; no links.", w1.payload, {
    bytes: 1297, digest: '898cffbb063bd7864b3f031b4d3699a70167caad753a96e5e9b5ebfd16719d4c',
  }),
  recordCase('W1r', 'W1 relabelled after capture to name a human decider: another digest (a tamper).', w1r, {
    bytes: 1163, digest: '94704964e73bfc848e17dd76e253e27952124d319023b752ff1251a6534317ee',
  }),
  recordCase('W2', "A human decision on a direct model call: one propose step whose actor is null.", w2.payload, {
    bytes: 907, digest: '71bcc81edb3e12119420c8a6fc8188a9206b1afd7c6e46a09dc409c480377a83',
  }),
  recordCase('W3', 'Two models and a human decide step, deriving from W2 in the same store (derivedFrom and root); the policy-form expectation.', w3.payload, {
    bytes: 3165, digest: '6fb46fa4724f9e1689a2a18fe465e8aedeaee6a5742878983a181084602b0e2e',
  }),
  recordCase('W3s', 'W3 with maxApprovedAmount 45000 after the review, re-hashed: contributions.binding reads decided_output_differs.', w3s, {
    bytes: 3165, digest: 'b20b48862767f129c6120eccc241cd1520edf40480eece96b75fb41569d019b5',
  }),
  recordCase('W5', "W4's issuance record: tzun:mandate, issue-mandate, the principal as decider.", w5.payload, {
    bytes: 633, digest: 'fb29b130c25c42d6ac72f1ea4123f0c542d6fefed9cfcaaa6b9a1b5e74af9844',
  }),
  recordCase('W6', "A record under W4's mandate: slot 41, total 5,230,000, confirm false; agent-mandated; a mandate link to W5.", w6.payload, {
    bytes: 1697, digest: '057a50035ba3eb6b0ae82b2cb8e1aa8e22bf8a223e5470c135cce67ab58766fe',
  }),
  recordCase('W7', 'A link record: a complaint recorded in another store (the subject, external) appeals W3.', w7.payload, {
    bytes: 811, digest: '9baa0f50a76ed0280d16be30dfe51571fb37b7952c144023a87ba1f61debf454',
  }),
];
for (const [id, env] of [['W1', w1], ['W2', w2], ['W3', w3], ['W5', w5], ['W6', w6], ['W7', w7]] as const) {
  agree(`${id} assembled digest`, env.integrity.canonicalDigest, records.find((r) => r.id === id)!.digest);
}

// ── output and step digests ─────────────────────────────────────────────
const outputDigests = [
  { label: "W1's proposal (aiOutput)", value: w1Output, digest: 'sha256:35f9924bbc25e4d34c48fbfd5a40e75c12048ecb92568b3e4f4be0e3510066e8' },
  { label: "W3's proposal (aiOutput)", value: w3Output, digest: 'sha256:acda70afa64735b0b4889f7ca04b6b80998031b2d82696e37b97b03331869b57' },
  { label: "W3's review", value: reviewOutput, digest: 'sha256:f59684773ae5ce28f65e4c311fa0052fb81e235ac322de987813ef39252d737f' },
  { label: "W3's decision { action, reason }", value: { action: w3Action, reason: w3Reason }, digest: 'sha256:ef9b809ada8800da4257ccfb6dacffbb62fe5d09ad8ab3adf1dbf236ffc9ad4a' },
  { label: "W3's proposal with its amount swapped after the review (W3s)", value: w3s.aiOutput, digest: 'sha256:137c3b2a21a338f02db7041a8c7409f8b70bb38bafb56ee7c7326d3063aadc9e' },
];
for (const o of outputDigests) {
  agree(`outputDigest(${o.label})`, prefixed(o.value), o.digest);
  agree(`engine outputDigest(${o.label})`, outputDigest(o.value), o.digest);
}
const stepDigests = [
  { record: 'W1', index: 0, step: w1.payload.contributions!.steps[0], digest: 'sha256:1cb437d573a5dddb00cf7f93763e47612f1fb8dc8835d8f73b8d2819104106af' },
  ...w3.payload.contributions!.steps.map((step, index) => ({
    record: 'W3', index, step,
    digest: [
      'sha256:32a1ccc01f6eb79975fef13137aca3f4984454bf779f62218b82a630c0d86a10',
      'sha256:c8eb7215f2d39fa10a06375e225c0b35e9dd2dec2cac1314fa8b023396ff7d8b',
      'sha256:a355a0cefe7b2020f5ff81eec4aef5a51349260813791f84b62935e4053485fd',
    ][index],
  })),
];
for (const s of stepDigests) {
  agree(`${s.record} step ${s.index} digest`, prefixed(s.step), s.digest);
  agree(`engine ${s.record} step ${s.index} digest`, stepDigest(s.step), s.digest);
}

// ── agent descriptors ───────────────────────────────────────────────────
const descriptorText =
  '{"derivation":"base","identities":["spiffe://claims.example/agent/triage"],"instructions":"sha256:be6682dd9f0ba8bbbb060e759803b0b71b69342105824467a8d918a191b391e0","keys":[{"alg":"EdDSA","attestation":null,"custody":"software","kid":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}],"models":["sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947"],"name":"claims-triage-agent","operator":{"organization":"Example Insurer","owner":"399bad81f76ef3e1a781d4edcf6eee0b54ce4cfc3304ca56b50d7457910c13b9"},"parent":null,"policy":"sha256:16c9ce7658ad1a8dd72bc047ce935212fc29b829818bac33e61546c3f9c57589","runtime":null,"tools":"sha256:d2269b9f0ab7e0a1ab7bf010b7f60ff9ab2fea2e6f728b666f0bc5e5ebf51ca9","v":"tzun-agent/1"}';
const descriptor = JSON.parse(descriptorText) as AgentDescriptor;
const unsortedDescriptor: AgentDescriptor = {
  ...descriptor,
  identities: ['spiffe://claims.example/agent/triage', 'spiffe://alpha.example/agent/triage'],
  keys: [descriptor.keys[0], { kid: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', alg: 'ES256', custody: 'hsm', attestation: 'tpm' }],
  models: ['sha256:' + 'ff'.repeat(32), descriptor.models[0]],
  runtime: { format: 'sev-snp', measurements: ['zz', 'aa'] },
};
const nonAsciiDescriptor: AgentDescriptor = {
  ...descriptor,
  identities: ['spiffe://claims.example/agent/é', 'spiffe://claims.example/agent/z'],
};
const byUtf8 = (a: string, b: string) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
const sortedCopy = (d: AgentDescriptor): AgentDescriptor => ({
  ...d,
  identities: [...d.identities].sort(byUtf8),
  keys: [...d.keys].sort((a, b) => byUtf8(a.kid, b.kid)),
  models: [...d.models].sort(byUtf8),
  runtime: d.runtime && { ...d.runtime, measurements: [...d.runtime.measurements].sort(byUtf8) },
});
const agentDescriptors = [
  ['the example agent descriptor, unchanged by the record revision', descriptor],
  ['a descriptor whose sets are supplied out of order; hashed sorted', unsortedDescriptor],
  ['a set with a non-ASCII member, sorted by UTF-8 bytes', nonAsciiDescriptor],
].map(([label, d]) => {
  const canonical = canonicalSerializeValue(sortedCopy(d as AgentDescriptor));
  return { label, descriptor: d, canonical, byteLength: Buffer.byteLength(canonical), digest: 'sha256:' + sha256Hex(canonical) };
});
agree('descriptor bytes', agentDescriptors[0].canonical, descriptorText);
agree('descriptor byte length', agentDescriptors[0].byteLength, 729);
agree('descriptor digest', agentDescriptors[0].digest, AGENT);
for (const d of agentDescriptors) {
  agree(`engine descriptor bytes (${d.label})`, canonicalSerializeAgentDescriptor(d.descriptor as AgentDescriptor), d.canonical);
  agree(`engine descriptor digest (${d.label})`, agentDescriptorDigest(d.descriptor as AgentDescriptor), d.digest);
}

// ── decider commitments ──────────────────────────────────────────────────
const commitmentCases: [string, Buffer][] = [
  ['acct:u-4821', Buffer.from(Array.from({ length: 32 }, (_, i) => i))],
  ['acct:u-4821', Buffer.alloc(32, 0xff)],
  ['spiffe://claims.example/agent/triage', createHash('sha256').update('salt one').digest()],
  [`desc:${AGENT}`, createHash('sha256').update('salt two').digest()],
];
const commitment = (innerId: string, salt: Buffer) =>
  'cmt:' + createHash('sha256').update('tzun-decider-cmt-v1', 'utf8').update(salt).update(innerId, 'utf8').digest('hex');
const deciderCommitments = commitmentCases.map(([innerId, salt]) => {
  const value = commitment(innerId, salt);
  agree(`commitment of ${innerId}`, deciderCommitment(innerId, salt), value);
  return { innerId, saltHex: salt.toString('hex'), saltBase64url: salt.toString('base64url'), commitment: value };
});
agree('the example commitment', deciderCommitments[0].commitment, 'cmt:68912cfb4b69d6b38fa0b954aa41794a8e1359afc929ee1147a4fc94ef4c14d9');
// A salt derived under an idempotency key: HMAC-SHA256(secret, tag ‖ len ‖ key ‖ len ‖ innerId).
const secret = Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i));
const lp = (text: string) => {
  const bytes = Buffer.from(text, 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(bytes.length);
  return Buffer.concat([len, bytes]);
};
const derivedSalt = createHmac('sha256', secret).update('tzun-cmt-salt-v1', 'utf8').update(lp('capture-7')).update(lp('acct:u-4821')).digest();
agree('derived salt', deciderCommitmentSalt(secret, 'capture-7', 'acct:u-4821'), derivedSalt.toString('base64url'));
const derivedSalts = [
  {
    secretHex: secret.toString('hex'), idempotencyKey: 'capture-7', innerId: 'acct:u-4821',
    saltBase64url: derivedSalt.toString('base64url'), commitment: commitment('acct:u-4821', derivedSalt),
  },
];

// ── mandate document, statement, assertion, event bodies ─────────────────
const mandateDocuments = [
  { label: "W4's document", document: w4Document, canonical: canonicalSerializeValue(w4Document), byteLength: 921, digest: w4MandateDigest },
];
const mandateStatements = [
  { label: "W4's statement: no signerName, policyDigest none", statement: w4Statement, canonical: canonicalSerializeValue(w4Statement), digest: w4StatementDigest, challenge: w4Challenge },
];
const mandateAssertions = [
  { label: "W4's Ed25519 assertion, the RFC 8037 Appendix A key over the statement challenge", assertion: w4Assertion, digest: w4AssertionDigest },
];
const eventBodies = [
  buildMandateEventBody({ event: 'issued', mandateDigest: w4MandateDigest, record: w5.integrity.canonicalDigest }),
  buildMandateEventBody({ event: 'revoked', mandateDigest: w4MandateDigest, record: '3b'.repeat(32), used: 43, totals: { paid: 5785000 } }),
  buildMandateEventBody({ event: 'superseded', mandateDigest: w4MandateDigest, record: '4c'.repeat(32), successor: '5d'.repeat(32), used: 43, totals: { paid: 5785000 } }),
  buildMandateEventBody({ event: 'expired', mandateDigest: w4MandateDigest, record: w5.integrity.canonicalDigest, used: 43, totals: { paid: 5785000 } }),
];
const mandateEventBodies = eventBodies.map((body) => {
  const canonical = canonicalSerializeValue(body);
  return { label: `${body.event}`, body, canonical, digest: sha256Hex(canonical) };
});
agree('W5 event digest', mandateEventBodies[0].digest, '82511c5907fe6cc93c23b40b0933d4576ea86af28700eddbadae0856ece9b7b3');
for (const e of mandateEventBodies) agree(`engine event digest (${e.label})`, mandateEventBodyDigest(e.body), e.digest);
const confirmationChallenges = [
  {
    label: "W6's confirmation challenge",
    digest: w6.integrity.canonicalDigest,
    challenge: createHash('sha256').update('tzun-confirm-v1' + w6.integrity.canonicalDigest).digest('base64url'),
  },
];
for (const c of confirmationChallenges) agree(`engine ${c.label}`, mandateConfirmationChallenge(c.digest), c.challenge);

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
const R = BigInt('0x' + createHash('sha256').update('vector r').digest('hex')) % P256_ORDER;
const sHigh = P256_ORDER - (BigInt('0x' + createHash('sha256').update('vector s').digest('hex')) % (P256_ORDER >> BigInt(1)));
const sLow = P256_ORDER - sHigh;
const authenticatorData = Buffer.concat([createHash('sha256').update('rp.example').digest(), Buffer.from([0x05, 0, 0, 0, 7])]);
const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: w4Challenge, origin: 'https://rp.example' }));
const assertionOf = (algorithm: string, signature: Buffer) => ({
  signature: signature.toString('base64url'),
  credentialKeyId: 'credential-1',
  algorithm,
  authenticatorData: authenticatorData.toString('base64url'),
  clientDataJSON: clientDataJSON.toString('base64url'),
});
const expectedDigest = (signature: Buffer) =>
  createHash('sha256')
    .update('tzun-assertion-v1', 'utf8')
    .update(createHash('sha256').update(authenticatorData).digest())
    .update(createHash('sha256').update(clientDataJSON).digest())
    .update(createHash('sha256').update(signature).digest())
    .digest('hex');
const minimalLowS = der(R, sLow);
const ed25519 = createHash('sha512').update('vector ed25519 signature').digest();
const assertionDigests = [
  { label: 'ES256, minimal DER, low S', assertion: assertionOf('ES256', minimalLowS), digest: expectedDigest(minimalLowS) },
  { label: 'ES256, the same signature with high S', assertion: assertionOf('ES256', der(R, sHigh)), digest: expectedDigest(minimalLowS) },
  { label: 'ES256, a non-minimal integer encoding', assertion: assertionOf('ES256', der(R, sLow, { padR: 1 })), digest: expectedDigest(minimalLowS) },
  { label: 'ES256, a long-form sequence length', assertion: assertionOf('ES256', der(R, sLow, { longLength: true })), digest: expectedDigest(minimalLowS) },
  { label: 'Ed25519, the signature as given', assertion: assertionOf('Ed25519', ed25519), digest: expectedDigest(ed25519) },
  { label: 'ES256, raw r||s is not DER', assertion: assertionOf('ES256', ed25519), digest: null },
  { label: 'ES256, trailing bytes after the sequence', assertion: assertionOf('ES256', Buffer.concat([minimalLowS, Buffer.from([0])])), digest: null },
];
for (const a of assertionDigests) agree(`assertion digest (${a.label})`, assertionDigest(a.assertion), a.digest);

process.stdout.write(
  JSON.stringify(
    {
      description:
        'Worked examples W1 to W7 of the v1.0 record as revised in 0.8.0: canonical bytes and digests every ' +
        'implementation must reproduce. Generated by scripts/generate-v1.0-worked-example-vectors.ts; do not edit by hand.',
      hashedFieldSet: FIELDS,
      records,
      outputDigests,
      stepDigests,
      agentDescriptors,
      deciderCommitments,
      derivedSalts,
      mandateDocuments,
      mandateStatements,
      mandateAssertions,
      mandateEventBodies,
      confirmationChallenges,
      assertionDigests,
    },
    null,
    2,
  ) + '\n',
);
