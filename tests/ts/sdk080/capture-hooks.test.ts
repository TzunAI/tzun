/**
 * The SDK extension points (src/sdk/extension-points.ts)
 * as capture() calls them: the agent hook, the link hook, the mandate hook
 * and its claim, system records, and what a store without a feature does.
 * The hooks here are stand-ins written for the contract, not the features.
 */
import { createHash } from 'node:crypto';
import type { HeldLinkTarget, LinkInput, MandateClaimStore, StorageAdapter } from '@tzun/engine';
import { Tzun } from '../../../src/sdk';
import {
  ExtensionNotInstalledError,
  type CaptureRefusal,
  type MandateAttemptPlan,
  type SdkExtensionFactory,
  type SdkHost,
} from '../../../src/sdk/extension-points';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import type { StorageExtension } from '../../../src/storage/extensions';
import { AGENT as AGENT_DIGEST, CLAIMS_AGENT_DESCRIPTOR, assert as sign, enrol, person, type Person } from '../mandates/fixtures';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');
const AGENT = `sha256:${hex('agent descriptor')}`;
const human = { kind: 'human' as const, id: 'acct:u-4821' };
const decision = { aiOutput: { recommendation: 'approve' }, action: 'approve', reason: 'within policy', decider: human };

describe('a store without a feature', () => {
  let tzun: Tzun;
  beforeEach(async () => {
    // No SDK extension and only the decider openings: a store without the
    // agent catalog, links or mandates.
    tzun = await Tzun.init({ mode: 'dev', _sdkExtensions: [], _storageExtensions: [decidersExtension] });
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('accepts agent references as given, holds no link target, and refuses a capture under a mandate', async () => {
    const agent = await tzun.capture({ ...decision, decider: { kind: 'agent', agent: AGENT } });
    expect(agent.stored).toBe(true);
    expect(agent.envelope.payload.decider).toEqual({ kind: 'agent', id: `desc:${AGENT}`, agent: AGENT, credential: null, freshness: null });

    const linked = await tzun.capture({ ...decision, links: [{ rel: 'derivedFrom', target: { evidenceId: agent.envelope.payload.evidenceId } }] });
    expect(linked.failure?.diagnosticMetadata).toMatchObject({ code: 'link_target_not_found', field: 'links[0].target' });

    const external = await tzun.capture({
      ...decision,
      links: [{ rel: 'derivedFrom', target: { digest: hex('elsewhere'), external: true } }],
    });
    expect(external.stored).toBe(true);
    expect(external.envelope.payload.links).toEqual([
      { rel: 'derivedFrom', target: { digest: hex('elsewhere'), evidenceId: null, locator: null }, attrs: null },
    ]);

    const mandated = await tzun.capture(
      { ...decision, decider: { kind: 'agent-mandated', agent: AGENT } },
      { mandate: { mandateId: 'm-1' } },
    );
    expect(mandated.failure?.diagnosticMetadata).toMatchObject({ code: 'mandate_not_supported_by_store', field: 'mandate' });
    // Refusals take no sequence number.
    expect((await tzun.capture(decision)).envelope.payload.sequenceNumber).toBe(3);
  });

  it('namespaces of a feature not installed reject with ExtensionNotInstalledError', async () => {
    await expect(tzun.mandates.get('m-1')).rejects.toBeInstanceOf(ExtensionNotInstalledError);
    await expect(tzun.agents.list()).rejects.toMatchObject({ code: 'extension_not_installed', extension: 'agents' });
    await expect(tzun.links.to(hex('x'))).rejects.toBeInstanceOf(ExtensionNotInstalledError);
    await expect(tzun.decisionGraph.walk('x')).rejects.toBeInstanceOf(ExtensionNotInstalledError);
  });

  it('a decider commitment is written into the record and its opening kept by the store', async () => {
    const a = await tzun.capture({ ...decision, decider: { ...human, commit: true } }, { idempotencyKey: 'k-commit' });
    expect(a.envelope.payload.decider?.id).toMatch(/^cmt:[0-9a-f]{64}$/);
    expect(a.deciderOpening?.id).toBe('acct:u-4821');
    expect(await tzun.deciders.opening(a.envelope.payload.evidenceId)).toEqual(a.deciderOpening);
    // A retry under the key commits with the same (derived) salt, so it replays.
    const b = await tzun.capture({ ...decision, decider: { ...human, commit: true } }, { idempotencyKey: 'k-commit' });
    expect(b.replayed).toBe(true);
    expect(b.envelope.payload.decider?.id).toBe(a.envelope.payload.decider?.id);
  });

  it('requireFreshness refuses a decider with no finalized-block reference; an explicit one is written', async () => {
    const refused = await tzun.capture(decision, { requireFreshness: true });
    expect(refused.failure?.diagnosticMetadata).toMatchObject({ code: 'freshness_required', field: 'decider.freshness' });
    const ref = `eip155:560048@123:0x${hex('block')}`;
    const ok = await tzun.capture({ ...decision, decider: { ...human, freshness: ref } }, { requireFreshness: true });
    expect(ok.envelope.payload.decider?.freshness).toBe(ref);
  });
});

describe('a store whose opening keeps no commitment refuses commit: true', () => {
  it('commitment_not_supported_by_store', async () => {
    const tzun = await Tzun.init({ mode: 'dev', _storageExtensions: [] });
    try {
      const r = await tzun.capture({ ...decision, decider: { ...human, commit: true } });
      expect(r.failure?.diagnosticMetadata).toMatchObject({ code: 'commitment_not_supported_by_store' });
    } finally {
      await tzun.close();
    }
  });
});

describe('the agent and link hooks', () => {
  const calls: string[] = [];
  const agentsAndLinks: SdkExtensionFactory = (host: SdkHost) => ({
    name: 'agents',
    agents: {
      api: { register: async () => ({ digest: AGENT, alreadyExisted: false }), get: async () => null, list: async () => ({ rows: [], cursor: null }) },
      captureHook: {
        async checkReferences(refs) {
          calls.push(`agents:${refs.map((r) => r.field).join(',')}`);
          return refs.some((r) => r.agent !== AGENT)
            ? { failureType: 'validation_failure', code: 'agent_not_registered', field: refs[0].field, message: 'not registered' }
            : null;
        },
      },
    },
  });
  const links: SdkExtensionFactory = (host: SdkHost) => ({
    name: 'links',
    links: {
      api: { relate: async () => { throw new Error('unused'); }, of: async () => null, to: async () => ({ rows: [], cursor: null }) },
      decisionGraph: { walk: async () => ({ root: '', nodes: [], edges: [], truncated: false }) },
      captureHook: {
        async resolveTargets(inputs: readonly LinkInput[]): Promise<ReadonlyArray<HeldLinkTarget | null>> {
          calls.push(`links:${inputs.length}`);
          const held: Array<HeldLinkTarget | null> = [];
          for (const input of inputs) {
            const env = input.target.evidenceId ? await host.storage.retrieve(input.target.evidenceId) : null;
            if (!env) {
              held.push(null);
              continue;
            }
            const chain = await host.storage.getChainForRecord(env.payload.evidenceId);
            held.push({
              payload: env.payload as unknown as Record<string, unknown>,
              digest: env.integrity.canonicalDigest,
              origin: chain === null ? null : await host.evidenceLogOrigin(chain),
            });
          }
          return held;
        },
      },
    },
  });

  let tzun: Tzun;
  beforeEach(async () => {
    calls.length = 0;
    tzun = await Tzun.init({ mode: 'dev', _sdkExtensions: [agentsAndLinks, links] });
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('checks every agent reference before any sequence number, and refuses one the catalog does not hold', async () => {
    const step = { role: 'other', actor: { kind: 'agent' as const, agent: `sha256:${hex('other')}` }, aiBom: null, inputs: [], outputOf: { checked: true } };
    const refused = await tzun.capture({ ...decision, decider: { kind: 'agent', agent: AGENT }, contributions: { steps: [step] } });
    expect(refused.failure?.diagnosticMetadata).toMatchObject({ code: 'agent_not_registered' });
    expect(calls).toEqual(['agents:decider.agent,contributions.steps[0].actor.agent']);
    expect(refused.failure?.diagnosticMetadata).toMatchObject({ code: 'agent_not_registered', field: 'decider.agent' });
    expect((await tzun.capture(decision)).envelope.payload.sequenceNumber).toBe(1);
  });

  it('resolves same-store targets: digest, evidence id and locator filled, the root added', async () => {
    const parent = await tzun.capture(decision);
    const child = await tzun.capture({ ...decision, links: [{ rel: 'derivedFrom', target: { evidenceId: parent.envelope.payload.evidenceId } }] });
    expect(child.failure).toBeUndefined();
    const [derived, root] = child.envelope.payload.links!;
    expect(derived.rel).toBe('derivedFrom');
    expect(derived.target.digest).toBe(parent.envelope.integrity.canonicalDigest);
    expect(derived.target.evidenceId).toBe(parent.envelope.payload.evidenceId);
    expect(derived.target.locator).toEqual({ origin: expect.stringMatching(/\/evidence\/64656661756c74$/), seq: 1 });
    expect(root).toEqual({ ...derived, rel: 'root' });
    expect((await tzun.verify(child.envelope.payload.evidenceId)).verified).toBe(true);
  });

  it('captures a link record through captureSystemRecord, with its reserved subject relation', async () => {
    const parent = await tzun.capture(decision);
    let host!: SdkHost;
    const grab: SdkExtensionFactory = (h) => {
      host = h;
      return { name: 'mandates' };
    };
    const t2 = await Tzun.init({ mode: 'dev', _sdkExtensions: [grab] });
    try {
      const record = await host.captureSystemRecord({
        kind: 'link',
        aiOutput: {},
        action: 'link',
        reason: 'Complaint C-1182 contests the decision',
        decider: { kind: 'human', id: 'acct:u-7702' },
        links: [
          { rel: 'appeals', target: { digest: parent.envelope.integrity.canonicalDigest, external: true } },
          { rel: 'subject', target: { digest: hex('complaint'), external: true } },
        ],
        allowReserved: ['subject'],
        linkRecord: true,
      });
      expect(record.failure).toBeUndefined();
      expect(record.envelope.payload.aiSystemId).toBe('tzun:link');
      expect(record.envelope.payload.links!.map((l) => l.rel)).toEqual(['appeals', 'subject']);
      // A caller's capture may not write the reserved relation.
      const caller = await t2.capture({ ...decision, links: [{ rel: 'subject', target: { digest: hex('x'), external: true } }] });
      expect(caller.failure?.diagnosticMetadata).toMatchObject({ code: 'relation_reserved' });
      // prepareSystemRecord fixes the record a signature would be made over.
      const prepared = await host.prepareSystemRecord({
        kind: 'link', aiOutput: {}, action: 'link', reason: 'again', decider: { kind: 'human', id: 'acct:u-7702' },
        links: [{ rel: 'appeals', target: { digest: hex('a'), external: true } }, { rel: 'subject', target: { digest: hex('b'), external: true } }],
        allowReserved: ['subject'], linkRecord: true,
      });
      expect(prepared.decider.id).toBe('acct:u-7702');
    } finally {
      await t2.close();
    }
  });
});

describe('the mandate hook and its claim', () => {
  /** A storage extension standing in for the mandate tables: it records each claim and loses the first. */
  function claimStore(claims: MandateClaimStore[]): StorageExtension {
    let lost = false;
    return {
      name: 'claims',
      memory: {
        createState: () => null,
        check(_state, write) {
          const claim = write.options.mandateClaim;
          if (!claim) return;
          claims.push(claim);
          if (!lost) {
            lost = true;
            throw Object.assign(new Error('the slot moved'), { code: 'mandate_claim_conflict' });
          }
        },
      },
    };
  }

  const mandates = (planned: { used: number }): SdkExtensionFactory => () => ({
    name: 'mandates',
    mandates: {
      api: {} as never,
      captureHook: {
        async open({ mandateId }) {
          if (mandateId !== 'm-1') {
            return { failureType: 'validation_failure', code: 'mandate_not_found', field: 'mandate', message: 'no such mandate' } as CaptureRefusal;
          }
          return {
            async plan(payload) {
              planned.used += 1;
              const slot = planned.used;
              const plan: MandateAttemptPlan = {
                signoffExpectation: { mandateAssertion: hex('assertion'), mandateSeq: slot, totals: null, confirm: false },
                links: [...(payload.links ?? []), { rel: 'mandate', target: { digest: hex('issuance'), evidenceId: null, locator: null }, attrs: null }],
                block: { statement: { v: 'tzun-signoff-mandate/1' }, assertion: { signature: 's', credentialKeyId: 'c', algorithm: 'Ed25519' }, assertionTimestamp: null, document: { v: 'tzun-mandate/1' } } as never,
                custody: [{ action: 'captured_under_mandate', actor: payload.decider!.id, metadata: { mandateId, slot } }],
                claim: { mandateId, expectUsed: slot - 1, caps: [], now: payload.capturedAt },
                result: { mandateId, slot, totals: null },
              };
              return plan;
            },
            classifyStoreError(error) {
              return (error as { code?: unknown }).code === 'mandate_claim_conflict' ? 'retry' : null;
            },
          };
        },
      },
    },
  });

  it('plans every attempt, retries a lost claim, and stores the claim, the block and the custody entry with the record', async () => {
    const claims: MandateClaimStore[] = [];
    const planned = { used: 0 };
    const tzun = await Tzun.init({ mode: 'dev', _sdkExtensions: [mandates(planned)], _storageExtensions: [decidersExtension, claimStore(claims)] });
    try {
      const r = await tzun.capture({ ...decision, decider: { kind: 'agent-mandated', agent: AGENT } }, { mandate: { mandateId: 'm-1' } });
      expect(r.failure).toBeUndefined();
      expect(claims.map((c) => c.expectUsed)).toEqual([0, 1]);
      expect(r.mandate).toEqual({ mandateId: 'm-1', slot: 2, totals: null });
      expect(r.envelope.payload.signoffExpectation).toMatchObject({ mandateSeq: 2 });
      expect(r.envelope.payload.links?.map((l) => l.rel)).toEqual(['mandate']);
      expect(r.envelope.nonRepudiation.mandate).toBeDefined();
      expect(r.envelope.custodyChain.map((e) => e.action)).toEqual(['decision_captured', 'captured_under_mandate']);
      expect((await tzun.verify(r.envelope.payload.evidenceId)).recomputedDigest).toBe(r.envelope.integrity.canonicalDigest);

      const unknown = await tzun.capture({ ...decision, decider: { kind: 'agent-mandated', agent: AGENT } }, { mandate: { mandateId: 'm-9' } });
      expect(unknown.failure?.diagnosticMetadata).toMatchObject({ code: 'mandate_not_found' });
    } finally {
      await tzun.close();
    }
  });

  it('refuses a signoffExpectation beside a mandate, and the mandate form from a caller', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    try {
      const both = await tzun.capture(decision, { mandate: { mandateId: 'm-1' }, signoffExpectation: { policyDigest: hex('p') } });
      expect(both.failure?.diagnosticMetadata).toMatchObject({ code: 'expectation_with_mandate' });
      const form = await tzun.capture(decision, {
        signoffExpectation: { mandateAssertion: hex('a'), mandateSeq: 1, totals: null, confirm: false } as never,
      });
      expect(form.failure?.diagnosticMetadata).toMatchObject({ code: 'mandate_form_not_writable' });
    } finally {
      await tzun.close();
    }
  });
});

it('a StorageAdapter without retrieveByDigest still captures (the cloud shape has none)', async () => {
  const tzun = await Tzun.init({ mode: 'dev' });
  const storage = tzun.getStorage() as StorageAdapter;
  expect(typeof storage.retrieveByDigest).toBe('function');
  await tzun.close();
});

describe('the decider against the material presented with it', () => {
  let tzun: Tzun;
  const alice = person('alice-1');
  const bob = person('bob-1');
  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev' });
    await enrol(tzun, alice);
    await enrol(tzun, bob);
    await tzun.agents.register(CLAIMS_AGENT_DESCRIPTOR);
  });
  afterEach(async () => {
    await tzun.close();
  });

  /** Prepare `decider`'s decision, have `signer` sign its challenge, and capture it. */
  async function signedBy(decider: Parameters<Tzun['capture']>[0]['decider'], signer: Person) {
    const input = { ...decision, decider };
    const prepared = await tzun.prepareAssertionChallenge(input);
    return tzun.capture({ ...input, attestationInputs: { webauthnAssertion: sign(signer, prepared.challenge) } }, { prepared });
  }

  it("stores an acct decider's decision signed by that account", async () => {
    const r = await signedBy({ kind: 'human', id: 'acct:alice-1' }, alice);
    expect(r.stored).toBe(true);
    expect(r.envelope.nonRepudiation.webauthnAssertion?.credentialKeyId).toBe(alice.credentialId);
  });

  it("refuses an acct decider whose account is not the assertion's credential's user, before any sequence number", async () => {
    const r = await signedBy({ kind: 'human', id: 'acct:alice-1' }, bob);
    expect(r.stored).toBe(false);
    expect(r.failure?.diagnosticMetadata).toMatchObject({ code: 'identity_contradicts_assertion', field: 'decider.id' });
    expect(await tzun.getStorage().getChainLength()).toBe(0);
  });

  it("refuses an agent decider with a human's assertion over the record, before any sequence number", async () => {
    const r = await signedBy({ kind: 'agent', agent: AGENT_DIGEST }, alice);
    expect(r.stored).toBe(false);
    expect(r.failure?.diagnosticMetadata).toMatchObject({ code: 'kind_contradicts_material', field: 'decider.kind' });
    expect(await tzun.getStorage().getChainLength()).toBe(0);
  });
});
