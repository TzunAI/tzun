/**
 * `tzun.agents` and the agent catalog's capture hook (src/sdk/agents)
 * through `Tzun.init()` on the memory, SQLite and Postgres
 * stores: register, get, list; capture refuses an agent reference the
 * catalog does not hold (`agent_not_registered`) and a policy engine whose
 * descriptor names a model (`agent_kind_mismatch`), before any sequence
 * number is taken; store-level verification resolves what capture accepted;
 * a store without the catalog accepts references as given.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type Database from 'better-sqlite3';
import { InvalidPaginationError } from '@tzun/engine';
import type { AgentDescriptor, TzunConfig } from '@tzun/engine';
import { Tzun } from '../../../src/sdk';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import { AgentCatalogUnsupportedError, InvalidAgentDescriptorError, agentsSdkExtension, agentsStorageExtension } from '../../../src/sdk/agents';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';
import { X12, descriptorNamed, policyEngineDescriptor } from './fixtures';

const dir = mkdtempSync(join(tmpdir(), 'tzun-test-agents-sdk-'));
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

const WITH_CATALOG = {
  _sdkExtensions: [agentsSdkExtension],
  _storageExtensions: [decidersExtension, agentsStorageExtension],
} as Partial<TzunConfig>;

interface Leg {
  name: 'memory' | 'sqlite' | 'postgres';
  config(): Promise<TzunConfig>;
}

let n = 0;
const pg = pgSuiteSchema('agents_sdk');
const legs: Leg[] = [
  { name: 'memory', config: async () => ({ mode: 'dev' }) },
  { name: 'sqlite', config: async () => ({ mode: 'dev', dbPath: join(dir, `agents-${++n}.db`) }) },
  ...(PG_TESTS_ENABLED
    ? [
        {
          name: 'postgres' as const,
          config: async (): Promise<TzunConfig> => {
            await pg.reset();
            return { mode: 'dev', dbUrl: pg.url };
          },
        },
      ]
    : []),
];

const decision = { aiOutput: { recommendation: 'pay' }, action: 'pay', reason: 'within the automatic-payment limit' };
const otherAgent = `sha256:${'ab'.repeat(32)}`;

function step(agent: string, kind: 'agent' | 'policy-engine' = 'agent') {
  return { role: 'other', actor: { kind, agent }, aiBom: null, inputs: [], outputOf: { checked: true } };
}

describe.each(legs)('the agent catalog through Tzun on $name', (leg) => {
  let tzun: Tzun;
  beforeEach(async () => {
    tzun = await Tzun.init({ ...(await leg.config()), ...WITH_CATALOG });
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('registers, reads and lists descriptors', async () => {
    const first = await tzun.agents.register(X12);
    expect(first).toEqual({ digest: 'sha256:eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f', alreadyExisted: false });
    expect(await tzun.agents.register(X12)).toEqual({ ...first, alreadyExisted: true });
    const row = await tzun.agents.get(first.digest);
    expect(row).toMatchObject({ digest: first.digest, name: 'claims-triage-agent', organization: 'Example Insurer', parent: null });
    expect(JSON.parse(row!.canonicalBytes)).toEqual(X12);
    expect(await tzun.agents.get(otherAgent)).toBeNull();

    const more = [descriptorNamed('review', 'Example Insurer', 1), descriptorNamed('review', 'Other Org', 2)];
    const digests = [first.digest];
    for (const d of more) digests.push((await tzun.agents.register(d)).digest);
    expect((await tzun.agents.list()).rows.map((r) => r.digest)).toEqual(digests);
    const page = await tzun.agents.list({ organization: 'Example Insurer', limit: 1 });
    expect(page.rows.map((r) => r.digest)).toEqual([digests[0]]);
    const next = await tzun.agents.list({ organization: 'Example Insurer', limit: 1, cursor: page.cursor! });
    expect(next).toEqual({ rows: [expect.objectContaining({ digest: digests[1] })], cursor: null });
    await expect(tzun.agents.list({ limit: 201 })).rejects.toBeInstanceOf(InvalidPaginationError);
  });

  it('refuses a descriptor that breaks the grammar or a writer limit', async () => {
    await expect(tzun.agents.register({ ...X12, name: 'x'.repeat(257) })).rejects.toBeInstanceOf(InvalidAgentDescriptorError);
    await expect(tzun.agents.register({ ...X12, models: ['not-a-digest'] })).rejects.toMatchObject({ code: 'invalid_agent_descriptor' });
    await expect(tzun.agents.register(null as unknown as AgentDescriptor)).rejects.toMatchObject({ code: 'invalid_agent_descriptor' });
    expect((await tzun.agents.list()).rows).toEqual([]);
  });

  it('captures a decision by a registered agent, and verification resolves the reference', async () => {
    const { digest } = await tzun.agents.register(X12);
    const r = await tzun.capture({ ...decision, decider: { kind: 'agent', agent: digest } });
    expect(r.failure).toBeUndefined();
    expect(r.envelope.payload.decider).toMatchObject({ kind: 'agent', id: `desc:${digest}`, agent: digest });
    const v = await tzun.verify(r.envelope.payload.evidenceId);
    expect(v.verified).toBe(true);
    expect(v.agents).toEqual([{ reference: digest, field: 'decider', resolved: true }]);
  });

  it('refuses an agent reference the catalog does not hold, before any sequence number', async () => {
    const decider = await tzun.capture({ ...decision, decider: { kind: 'agent', agent: otherAgent } });
    expect(decider.stored).toBe(false);
    expect(decider.failure).toMatchObject({ failureType: 'validation_failure' });
    expect(decider.failure!.diagnosticMetadata).toMatchObject({ code: 'agent_not_registered', reason: 'agent_not_registered', field: 'decider.agent' });
    expect(JSON.stringify(decider.failure!.diagnosticMetadata)).not.toContain(otherAgent);

    const { digest } = await tzun.agents.register(X12);
    const actor = await tzun.capture({
      ...decision,
      decider: { kind: 'agent', agent: digest },
      contributions: { steps: [step(digest), step(otherAgent)] },
    });
    expect(actor.failure!.diagnosticMetadata).toMatchObject({ code: 'agent_not_registered', field: 'contributions.steps[1].actor.agent' });

    const ok = await tzun.capture({ ...decision, decider: { kind: 'human', id: 'acct:u-4821' } });
    expect(ok.envelope.payload.sequenceNumber).toBe(1);
  });

  it('refuses a policy engine whose descriptor names a model, as decider or step actor', async () => {
    const modelBearing = (await tzun.agents.register(X12)).digest;
    const engine = (await tzun.agents.register(policyEngineDescriptor())).digest;

    const refused = await tzun.capture({ ...decision, decider: { kind: 'policy-engine', agent: modelBearing } });
    expect(refused.failure!.diagnosticMetadata).toMatchObject({ code: 'agent_kind_mismatch', field: 'decider.agent' });
    const actor = await tzun.capture({
      ...decision,
      decider: { kind: 'human', id: 'acct:u-4821' },
      contributions: { steps: [step(engine, 'policy-engine'), step(modelBearing, 'policy-engine')] },
    });
    expect(actor.failure!.diagnosticMetadata).toMatchObject({ code: 'agent_kind_mismatch', field: 'contributions.steps[1].actor.agent' });

    // The same model-bearing descriptor is a valid agent; a policy engine whose descriptor names no model is accepted.
    const asAgent = await tzun.capture({ ...decision, decider: { kind: 'policy-engine', agent: engine }, contributions: { steps: [step(modelBearing)] } });
    expect(asAgent.failure).toBeUndefined();
    const v = await tzun.verify(asAgent.envelope.payload.evidenceId);
    expect(v.agents).toEqual([
      { reference: engine, field: 'decider', resolved: true },
      { reference: modelBearing, field: 'contributions.steps[0].actor', resolved: true },
    ]);
    expect(asAgent.envelope.payload.sequenceNumber).toBe(1);
  });
});

describe('a store whose catalog row was rewritten', () => {
  it('capture refuses the reference and verification reports the row, with the same reason', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: join(dir, `rewritten-${++n}.db`), ...WITH_CATALOG });
    try {
      const { digest } = await tzun.agents.register(X12);
      const before = await tzun.capture({ ...decision, decider: { kind: 'agent', agent: digest } });
      expect(before.failure).toBeUndefined();
      const db = (tzun.getStorage() as unknown as { db: Database.Database }).db;
      db.exec('DROP TRIGGER agent_descriptors_block_update');
      db.prepare("UPDATE agent_descriptors SET canonical_bytes = replace(canonical_bytes, 'Example Insurer', 'Other Insurer') WHERE digest = ?").run(digest);

      const after = await tzun.capture({ ...decision, decider: { kind: 'agent', agent: digest } });
      expect(after.failure!.diagnosticMetadata).toMatchObject({ code: 'agent_not_registered', field: 'decider.agent', catalog: 'digest_mismatch' });
      const v = await tzun.verify(before.envelope.payload.evidenceId);
      expect(v.agents).toEqual([{ reference: digest, field: 'decider', resolved: false, reason: 'digest_mismatch' }]);
    } finally {
      await tzun.close();
    }
  });
});

describe('a store without the catalog', () => {
  let tzun: Tzun;
  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev', _sdkExtensions: [agentsSdkExtension], _storageExtensions: [decidersExtension] } as TzunConfig);
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('accepts agent references as given, and verification reports them catalog_absent', async () => {
    const r = await tzun.capture({ ...decision, decider: { kind: 'policy-engine', agent: otherAgent } });
    expect(r.failure).toBeUndefined();
    expect((await tzun.verify(r.envelope.payload.evidenceId)).agents).toEqual([
      { reference: otherAgent, field: 'decider', resolved: false, reason: 'catalog_absent' },
    ]);
  });

  it('refuses register, get and list with agent_not_supported_by_store', async () => {
    await expect(tzun.agents.register(X12)).rejects.toBeInstanceOf(AgentCatalogUnsupportedError);
    await expect(tzun.agents.get(otherAgent)).rejects.toMatchObject({ code: 'agent_not_supported_by_store' });
    await expect(tzun.agents.list()).rejects.toMatchObject({ code: 'agent_not_supported_by_store' });
  });
});
