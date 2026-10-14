/**
 * The v1.0 record as revised in place for 0.8.0: the worked
 * examples W1, W1r, W2, W3, W3s and W7 built by the engine's own builders,
 * the payload gate every writer runs, and the record-rule rows a reader
 * reports, from the record alone and at store level.
 */
import { canonicalSerialize } from './canonical';
import { buildContributions, singleModel } from './contributions';
import { computeDigest } from './digest';
import { assembleEnvelope, buildEvidencePayload, EnvelopeInputError } from './envelope';
import { buildLinks } from './links';
import { payloadRecordRuleViolation } from './record-rules';
import { CURRENT_SCHEMA_VERSION, SchemaRegistry, V1_0_HASHED_FIELDS } from './schema-registry';
import { verifyEnvelope } from './verify';
import { agentDescriptorDigest, canonicalSerializeAgentDescriptor } from './agent';
import type { AgentDescriptor } from './types/agent';
import type { AiBom } from './types/ai-bom';
import type { EvidenceEnvelope, EnvelopeInput } from './types/evidence';
import type { HeldLinkTarget } from './types/links';
import type { StorageAdapter } from './types/storage-interface';

const AGENT = 'sha256:eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f';
const MODEL = 'sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947';
const ORIGIN = 'test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/6c656e64696e67';
type InferenceParameters = NonNullable<AiBom['inferenceParameters']>;
const bom = (md: string, ip: InferenceParameters | null = null): AiBom => ({
  modelDescriptorDigest: md, vendorFingerprint: null, promptTemplate: null, inferenceParameters: ip, infrastructure: null,
});
const human = (id: string) => ({ kind: 'human' as const, id, agent: null, credential: null, freshness: null });

/** Assemble, and return the envelope with the canonical byte length of its hashed object. */
function assemble(input: EnvelopeInput, options: Parameters<typeof assembleEnvelope>[1]) {
  const env = assembleEnvelope(input, options);
  const bytes = Buffer.byteLength(canonicalSerialize(env.payload as unknown as Record<string, unknown>, [...V1_0_HASHED_FIELDS]));
  return { env, bytes };
}

function w1(kind: 'agent' | 'human' = 'agent') {
  const aiOutput = { amount: 1250, recommendation: 'pay' };
  const decider = {
    kind: 'agent' as const,
    id: `desc:${AGENT}`,
    agent: AGENT,
    credential: 'e0d80c85a2b54cb68567fc4f7a56f20f321839af3d8f888df8b90b0a6920b386',
    freshness: 'eip155:1@9123456:0x8ae3e2d5ddeee120de1e2e58f78ed0ed9c7b7ead28098938757d597d09c3f64c',
  };
  const ctx = { decider, action: 'pay', reason: 'Amount below the automatic-payment limit; documents complete', aiOutput };
  const contributions = buildContributions(singleModel(bom(MODEL), { actor: { kind: 'agent', agent: AGENT } }), ctx);
  const built = assemble(
    { aiSystemId: 'claims-model', aiOutput, action: ctx.action, reason: ctx.reason, decider, contributions },
    { evidenceId: '5f0c1f0e-2222-4b2b-9b2b-000000000041', sequenceNumber: 41, capturedAt: '2026-09-30T14:03:11.000Z' },
  );
  if (kind === 'human') {
    built.env.payload.decider = { ...built.env.payload.decider!, kind: 'human', id: 'acct:u-4821', agent: null };
  }
  return built;
}

function w2() {
  const aiOutput = { missingDocuments: 0, route: 'underwriting' };
  const decider = human('acct:u-4821');
  const ctx = { decider, action: 'route', reason: 'Application complete; route to underwriting', aiOutput };
  const ip = { temperature: 0, topP: null, maxTokens: 400, seed: null, stopSequences: null };
  return assemble(
    { aiSystemId: 'intake-model', aiOutput, action: ctx.action, reason: ctx.reason, decider, contributions: buildContributions(singleModel(bom('sha256:' + '0c'.repeat(32), ip)), ctx) },
    { evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000006', sequenceNumber: 6, capturedAt: '2026-10-05T15:01:00.000Z' },
  );
}

const heldOf = (env: EvidenceEnvelope, origin: string | null = ORIGIN): HeldLinkTarget => ({
  payload: env.payload as unknown as Record<string, unknown>,
  digest: env.integrity.canonicalDigest,
  origin,
});

function w3(maxApprovedAmount = 25000) {
  const parent = w2().env;
  const A1 = 'sha256:' + 'a1'.repeat(32);
  const B2 = 'sha256:' + 'b2'.repeat(32);
  const ip = { temperature: 0, topP: null, maxTokens: 800, seed: null, stopSequences: null };
  const aiOutput = { maxApprovedAmount, recommendation: 'approve', riskScore: 31 };
  const decider = human('acct:u-4821');
  const action = 'approve';
  const reason = 'Income verified; reviewer found no fair-lending concerns';
  const ctx = { decider, action, reason, aiOutput: { maxApprovedAmount: 25000, recommendation: 'approve', riskScore: 31 } };
  const proposal = 'sha256:acda70afa64735b0b4889f7ca04b6b80998031b2d82696e37b97b03331869b57';
  const review = { factors: ['debtToIncome', 'incomeStability'], verdict: 'approve' };
  const contributions = buildContributions(
    {
      steps: [
        { role: 'propose:underwriting', actor: { kind: 'agent', agent: A1 }, aiBom: bom('sha256:' + '0a'.repeat(32), ip), inputs: [`sha256:${parent.integrity.canonicalDigest}`] },
        { role: 'review:fair-lending', actor: { kind: 'agent', agent: B2 }, aiBom: bom('sha256:' + '0b'.repeat(32), ip), inputs: [proposal], outputOf: review, verdict: 'approve', reason: 'No protected-class proxies in the factors' },
        { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null }, inputs: [proposal, 'sha256:f59684773ae5ce28f65e4c311fa0052fb81e235ac322de987813ef39252d737f'], verdict: 'approve' },
      ],
    },
    ctx,
  );
  const links = buildLinks([{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }], { held: [heldOf(parent)] });
  const built = assemble(
    { aiSystemId: 'lending-model', aiOutput: { maxApprovedAmount: 25000, recommendation: 'approve', riskScore: 31 }, action, reason, decider, contributions, links },
    {
      evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000007', sequenceNumber: 7, capturedAt: '2026-10-05T15:04:05.000Z',
      signoffExpectation: { policyDigest: 'c6f7fb5297c99674b01b72497dafdd6cdbae77553de269ff81dc1adff5873e3a' },
    },
  );
  if (maxApprovedAmount !== 25000) {
    // The swap after the review, re-hashed by a writer that hashed it anyway.
    (built.env.payload.aiOutput as Record<string, unknown>).maxApprovedAmount = maxApprovedAmount;
    built.env.integrity.canonicalDigest = computeDigest(canonicalSerialize(built.env.payload as never, [...V1_0_HASHED_FIELDS]));
  }
  return { ...built, parent };
}

function w7() {
  const { env: target } = w3();
  const links = buildLinks(
    [
      { rel: 'appeals', target: { evidenceId: target.payload.evidenceId } },
      { rel: 'subject', target: { digest: 'c0'.repeat(32), external: true } },
    ],
    { held: [heldOf(target), null], allowReserved: ['subject'], linkRecord: true },
  );
  return {
    ...assemble(
      {
        aiSystemId: 'tzun:link', aiOutput: {}, action: 'link', reason: 'Complaint C-1182 contests the underwriting decision',
        decider: human('acct:u-7702'), contributions: null, links,
      },
      { evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000019', sequenceNumber: 19, capturedAt: '2026-10-19T09:30:00.000Z', systemRecord: 'link' },
    ),
    target,
  };
}

describe('the registry (Record §4.1)', () => {
  it('holds one version, v1.0, with the eleven names', () => {
    const registry = new SchemaRegistry();
    expect(registry.list().map((v) => v.versionId)).toEqual(['v1.0']);
    expect(CURRENT_SCHEMA_VERSION).toBe('v1.0');
    expect(registry.get('v1.0')!.hashedFieldSet).toEqual([
      'action', 'aiOutput', 'aiSystemId', 'capturedAt', 'contributions', 'decider', 'evidenceId', 'links', 'reason',
      'sequenceNumber', 'signoffExpectation',
    ]);
    expect(registry.get('v1.1')).toBeUndefined();
  });
});

describe('the worked examples, built by the engine', () => {
  it.each([
    ['W1', () => w1(), 1297, '898cffbb063bd7864b3f031b4d3699a70167caad753a96e5e9b5ebfd16719d4c'],
    ['W2', () => w2(), 907, '71bcc81edb3e12119420c8a6fc8188a9206b1afd7c6e46a09dc409c480377a83'],
    ['W3', () => w3(), 3165, '6fb46fa4724f9e1689a2a18fe465e8aedeaee6a5742878983a181084602b0e2e'],
    ['W7', () => w7(), 811, '9baa0f50a76ed0280d16be30dfe51571fb37b7952c144023a87ba1f61debf454'],
  ])('%s: its canonical bytes and digest', (_id, build, bytes, digest) => {
    const r = build();
    expect(r.bytes).toBe(bytes);
    expect(r.env.integrity.canonicalDigest).toBe(digest);
    // Each example sits mid-chain without its predecessor, so only the digest is read here.
    expect(verifyEnvelope(r.env).recomputedDigest).toBe(digest);
  });

  it('W1r: relabelling the agent decider human is a digest mismatch', () => {
    const { env } = w1('human');
    const recomputed = computeDigest(canonicalSerialize(env.payload as never, [...V1_0_HASHED_FIELDS]));
    expect(recomputed).toBe('94704964e73bfc848e17dd76e253e27952124d319023b752ff1251a6534317ee');
    const r = verifyEnvelope(env);
    expect(r.recomputedDigest).not.toBe(r.storedDigest);
    expect(r.decider?.reason).toBe('digest_invalid');
  });

  it('W3s: the amount swapped after the review, re-hashed, fails decided_output_differs from its own bytes', () => {
    const { env } = w3(45000);
    expect(env.integrity.canonicalDigest).toBe('b20b48862767f129c6120eccc241cd1520edf40480eece96b75fb41569d019b5');
    const result = verifyEnvelope(env);
    expect(result.recomputedDigest).toBe(result.storedDigest);
    expect(result.contributions?.outcome).toBe('checked-correct');
    expect(result.contributions?.binding).toMatchObject({
      outcome: 'checked-wrong', reason: 'decided_output_differs',
      failedDigest: 'sha256:acda70afa64735b0b4889f7ca04b6b80998031b2d82696e37b97b03331869b57',
    });
  });
});

describe('the record-rule rows of verifyEnvelope', () => {
  it('W1: an agent decider, a list of one, no links', () => {
    const r = verifyEnvelope(w1().env);
    expect(r.decider).toMatchObject({ outcome: 'checked-correct', kind: 'agent', level: 'agent-asserted' });
    expect(r.contributions).toMatchObject({ outcome: 'checked-correct', steps: 1, models: [MODEL], decidingStep: 'record' });
    expect(r.links).toEqual({ outcome: 'not-checked', valid: null, reason: 'absent', relations: [], edges: [] });
    expect(r.unhashedPayloadMembers).toEqual([]);
    expect(r.mandate).toBeUndefined();
  });

  it('W3: two links, each relation checked from the record alone, each edge abstaining', () => {
    const r = verifyEnvelope(w3().env);
    expect(r.links).toMatchObject({ outcome: 'checked-correct', count: 2, relationNames: ['derivedFrom', 'root'] });
    expect(r.links!.relations.map((x) => x.outcome)).toEqual(['checked-correct', 'checked-correct']);
    expect(r.links!.edges.map((x) => x.reason)).toEqual(['unsupported_link_edge', 'unsupported_link_edge']);
    expect(r.contributions).toMatchObject({ decidingStep: 2, binding: { outcome: 'checked-correct', approvals: [1] } });
  });

  it('W7: a link record, its appeals target held at store level', () => {
    const { env, target } = w7();
    expect(verifyEnvelope(env).links?.outcome).toBe('checked-correct');
    const held = verifyEnvelope(env, undefined, undefined, {
      storage: {} as StorageAdapter,
      linkTargets: { byDigest: (d) => (d === target.integrity.canonicalDigest ? heldOf(target) : null) },
    });
    return held.then((r) => {
      expect(r.links!.relations.map((x) => [x.rel, x.outcome, x.targetHeld])).toEqual([
        ['appeals', 'checked-correct', true],
        ['subject', 'checked-correct', false],
      ]);
    });
  });

  it('reports an unhashed payload member, which changes no digest', () => {
    const { env } = w2();
    (env.payload as unknown as Record<string, unknown>).aiBom = bom(MODEL);
    (env.payload as unknown as Record<string, unknown>).humanReason = 'forged';
    const r = verifyEnvelope(env);
    expect(r.recomputedDigest).toBe(r.storedDigest);
    expect(r.unhashedPayloadMembers).toEqual(['aiBom', 'humanReason']);
  });

  it('reports digest_invalid for every row of a record whose digest does not hold', () => {
    const { env } = w3();
    env.payload.reason = 'rewritten';
    const r = verifyEnvelope(env);
    expect(r.decider?.reason).toBe('digest_invalid');
    expect(r.contributions?.reason).toBe('digest_invalid');
    expect(r.links?.reason).toBe('digest_invalid');
  });

  it('an unregistered schema version is schemaValid false and reports no rows', () => {
    const { env } = w2();
    env.payload.schemaVersion = 'v1.1';
    const r = verifyEnvelope(env);
    expect(r.schemaValid).toBe(false);
    expect(r.decider).toBeUndefined();
  });
});

describe('the payload gate (payloadRecordRuleViolation)', () => {
  const good = () => JSON.parse(JSON.stringify(w2().env.payload)) as Record<string, unknown>;

  it('accepts an SDK-built payload', () => {
    expect(payloadRecordRuleViolation(good())).toBeNull();
    expect(payloadRecordRuleViolation(w3().env.payload)).toBeNull();
    expect(payloadRecordRuleViolation(w7().env.payload, { systemRecord: 'link' })).toBeNull();
    // Each kind admits only its own reserved id: a link gate refuses mandate material, and the reverse.
    expect(payloadRecordRuleViolation(w7().env.payload, { systemRecord: 'mandate' })).toMatchObject({ code: 'reserved_ai_system_id' });
  });

  it.each([
    ['humanAction (renamed)', (p: any) => { p.humanAction = 'x'; }, 'payload', 'renamed_field'],
    ['reviewer (renamed)', (p: any) => { p.reviewer = 'x'; }, 'payload', 'renamed_field'],
    ['a top-level aiBom (moved)', (p: any) => { p.aiBom = null; }, 'payload', 'moved_field'],
    ['a lineage member (moved)', (p: any) => { p.lineage = null; }, 'payload', 'moved_field'],
    ['schemaVersion v1.1', (p: any) => { p.schemaVersion = 'v1.1'; }, 'payload', 'unsupported_schema_version'],
    ['an unknown member', (p: any) => { p.note = 'x'; }, 'payload', 'unknown_payload_member'],
    ['a missing member', (p: any) => { delete p.links; }, 'payload', 'missing_members'],
    ['a reserved aiSystemId', (p: any) => { p.aiSystemId = 'tzun:link'; }, 'payload', 'reserved_ai_system_id'],
    ['a decider of null', (p: any) => { p.decider = null; }, 'decider', 'not_an_object'],
    ['a malformed step', (p: any) => { p.contributions.steps[0].actor = null; p.contributions.steps[0].aiBom = null; }, 'contributions', 'actor_required'],
    ['links []', (p: any) => { p.links = []; }, 'links', 'empty_links'],
    ['a root alone', (p: any) => { p.links = [{ rel: 'root', target: { digest: '11'.repeat(32), evidenceId: null, locator: null }, attrs: null }]; }, 'links', 'root_without_lineage'],
    ['the mandate form with no mandate link', (p: any) => {
      p.decider = { kind: 'agent-mandated', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null };
      p.contributions = null;
      p.signoffExpectation = { mandateAssertion: '11'.repeat(32), mandateSeq: 1, totals: null, confirm: false };
    }, 'links', 'required_link_missing'],
    ['an agent kind under the session form', (p: any) => {
      p.decider = { kind: 'agent', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null };
      p.contributions = null;
      p.signoffExpectation = { statementDigest: '11'.repeat(32), sessionSeq: 1 };
    }, 'decider', 'kind_contradicts_expectation'],
  ])('refuses %s', (_name, mutate, rule, code) => {
    const p = good();
    mutate(p);
    expect(payloadRecordRuleViolation(p)).toMatchObject({ rule, code });
  });

  it('refuses the renamed and moved fields on the capture input too, before building anything', () => {
    const input = { aiOutput: {}, action: 'a', reason: 'r', decider: human('acct:u-1') };
    expect(() => buildEvidencePayload({ ...input, humanReason: 'x' } as never)).toThrow(
      expect.objectContaining({ code: 'renamed_field', field: 'humanReason' }),
    );
    expect(() => buildEvidencePayload({ ...input, aiBom: null } as never)).toThrow(
      expect.objectContaining({ code: 'moved_field', field: 'aiBom' }),
    );
    expect(() => buildEvidencePayload({ ...input, lineage: null } as never)).toThrow(EnvelopeInputError);
    expect(buildEvidencePayload(input)).toMatchObject({ schemaVersion: 'v1.0', contributions: null, links: null, signoffExpectation: null });
  });

  it('caps the hashed object at 256 KiB', () => {
    const input = { aiOutput: { blob: 'x'.repeat(256 * 1024) }, action: 'a', reason: 'r', decider: human('acct:u-1') };
    expect(() => buildEvidencePayload(input)).toThrow(expect.objectContaining({ code: 'payload_too_large' }));
  });

  it('writes the custody actor from the decider', () => {
    expect(w2().env.custodyChain[0]).toMatchObject({ action: 'decision_captured', actor: 'acct:u-4821' });
  });
});

describe('store-level verification', () => {
  const descriptorText =
    '{"derivation":"base","identities":["spiffe://claims.example/agent/triage"],"instructions":"sha256:be6682dd9f0ba8bbbb060e759803b0b71b69342105824467a8d918a191b391e0","keys":[{"alg":"EdDSA","attestation":null,"custody":"software","kid":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}],"models":["sha256:6c9556bc8e35e7701b44ecee10c605a4db9fdf082e6856681db7d7dd1ca3a947"],"name":"claims-triage-agent","operator":{"organization":"Example Insurer","owner":"399bad81f76ef3e1a781d4edcf6eee0b54ce4cfc3304ca56b50d7457910c13b9"},"parent":null,"policy":"sha256:16c9ce7658ad1a8dd72bc047ce935212fc29b829818bac33e61546c3f9c57589","runtime":null,"tools":"sha256:d2269b9f0ab7e0a1ab7bf010b7f60ff9ab2fea2e6f728b666f0bc5e5ebf51ca9","v":"tzun-agent/1"}';
  const descriptor = JSON.parse(descriptorText) as AgentDescriptor;
  const modelRow = (digest: string, parent: string | null) => {
    const d = { integrityTier: 'vendor-asserted', derivation: null, trainedBy: null, parentModelDescriptorDigest: parent };
    return { canonicalBytes: JSON.stringify(d), descriptor: d, digest };
  };

  it('resolves each step model, one lineage entry per model-bearing step, incidents naming the step', async () => {
    const { env } = w3();
    const leafA = 'sha256:' + '0a'.repeat(32);
    const storage = {
      getModelDescriptor: async (digest: string) => (digest === leafA ? modelRow(digest, null) : null),
    } as unknown as StorageAdapter;
    const r = await verifyEnvelope(env, undefined, undefined, { storage, walkLineage: true });
    // Step 0's row does not hash to its digest (the test row is not a real descriptor); step 1's is missing.
    expect(r.tamperIncidents).toEqual([
      expect.objectContaining({ type: 'descriptor_digest_mismatch', step: 0, claimedDigest: leafA }),
      expect.objectContaining({ type: 'descriptor_resolution_failure', step: 1, modelDescriptorDigest: 'sha256:' + '0b'.repeat(32) }),
    ]);
    expect(r.modelLineage).toEqual([
      { step: 0, descriptorDigest: leafA, lineage: [{ descriptorDigest: leafA, integrityTier: 'vendor-asserted', derivation: null, trainedBy: null }] },
      { step: 1, descriptorDigest: 'sha256:' + '0b'.repeat(32), lineage: [] },
    ]);
    expect(r.verified).toBe(false);
  });

  it('resolves agent references against the catalog, re-hashing the stored bytes', async () => {
    const { env } = w1();
    const row = { digest: AGENT, canonicalBytes: canonicalSerializeAgentDescriptor(descriptor), name: 'n', organization: 'o', parent: null, registeredAt: '' };
    expect(agentDescriptorDigest(descriptor)).toBe(AGENT);
    const withCatalog = { getAgentDescriptor: async (d: string) => (d === AGENT ? row : null) } as unknown as StorageAdapter;
    expect((await verifyEnvelope(env, undefined, undefined, { storage: withCatalog })).agents).toEqual([
      { reference: AGENT, field: 'decider', resolved: true },
      { reference: AGENT, field: 'contributions.steps[0].actor', resolved: true },
    ]);
    const without = {} as StorageAdapter;
    expect((await verifyEnvelope(env, undefined, undefined, { storage: without })).agents![0]).toMatchObject({ resolved: false, reason: 'catalog_absent' });
    const tampered = { getAgentDescriptor: async () => ({ ...row, canonicalBytes: row.canonicalBytes.replace('claims-triage-agent', 'other-agent') }) } as unknown as StorageAdapter;
    expect((await verifyEnvelope(env, undefined, undefined, { storage: tampered })).agents![0]).toMatchObject({ reason: 'digest_mismatch' });
    const missing = { getAgentDescriptor: async () => null } as unknown as StorageAdapter;
    expect((await verifyEnvelope(env, undefined, undefined, { storage: missing })).agents![0]).toMatchObject({ reason: 'not_registered' });
  });

  it('a policy engine whose descriptor names a model is agent_kind_mismatch', async () => {
    const { env } = w1();
    env.payload.decider = { ...env.payload.decider!, kind: 'policy-engine' };
    env.payload.contributions!.steps[0].actor = { ...env.payload.contributions!.steps[0].actor!, kind: 'policy-engine' };
    const row = { digest: AGENT, canonicalBytes: canonicalSerializeAgentDescriptor(descriptor), name: 'n', organization: 'o', parent: null, registeredAt: '' };
    const storage = { getAgentDescriptor: async () => row } as unknown as StorageAdapter;
    expect((await verifyEnvelope(env, undefined, undefined, { storage })).agents![0]).toMatchObject({ resolved: false, reason: 'agent_kind_mismatch' });
  });

  it('resolves link targets by digest through the store, with their chain origin and the openings', async () => {
    const { env, parent } = w3();
    const storage = {
      retrieveByDigest: async (d: string) => (d === parent.integrity.canonicalDigest ? parent : null),
      getChainForRecord: async () => 'lending',
      getBySequenceRange: async () => [],
    } as unknown as StorageAdapter;
    const evidenceLogOrigin = (chainId: string) => `test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/${Buffer.from(chainId).toString('hex')}`;
    const r = await verifyEnvelope(env, undefined, undefined, { storage, evidenceLogOrigin });
    expect(r.links!.relations.map((x) => [x.rel, x.outcome, x.targetHeld])).toEqual([
      ['derivedFrom', 'checked-correct', true],
      ['root', 'checked-correct', true],
    ]);
    // Another chain's origin for the target: the locator no longer agrees.
    const elsewhere = await verifyEnvelope(env, undefined, undefined, { storage: { ...storage, getChainForRecord: async () => 'other' } as StorageAdapter, evidenceLogOrigin });
    expect(elsewhere.links!.relations[0]).toMatchObject({ reason: 'link_target_mismatch', member: 'locator' });
  });
});
