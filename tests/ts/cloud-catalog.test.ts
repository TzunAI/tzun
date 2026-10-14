// The cloud transport's model and agent catalogs (SDK 0.8.0 cloud catalog
// contract): `HttpStorageAdapter` registers and reads descriptors through the
// platform's key-authenticated endpoints, so a wrapped vendor call in cloud
// mode records its model, and answers as a store without the catalog when the
// platform does not serve them.
//
// NON-VACUITY: every "falls back" case is paired with the same call recording
// the model, or resolving the reference, against a platform that serves the
// catalog (tests/ts/helpers/fake-cloud-platform.ts implements the contract).
import {
  CATALOG_REPROBE_MS,
  HttpStorageAdapter,
  HttpTransport,
  ModelCatalogUnsupportedError,
  TzunCatalogError,
} from '../../src/sdk/http-transport';
import { AgentCatalogUnsupportedError } from '../../src/storage/agent-sql';
import { Tzun } from '../../src/sdk/index';
import { agentDescriptorDigest, canonicalSerializeAgentDescriptor, type ModelDescriptor } from '@tzun/engine';
import { fakePlatform, modelDescriptor, modelDigest } from './helpers/fake-cloud-platform';
import { descriptorNamed, policyEngineDescriptor } from './agents/fixtures';

const SECRET_KEY = 'sk_test_cloud_catalog_secret';
const API_URL = 'https://api.example.test';

function adapterOver(fetchFn: typeof fetch): HttpStorageAdapter {
  return new HttpStorageAdapter(new HttpTransport({ apiKey: SECRET_KEY, apiUrl: API_URL, fetchFn }));
}

function answering(status: number, body: unknown, calls: string[] = []): typeof fetch {
  return (async (url: string, init: { method?: string } = {}) => {
    calls.push(`${init.method ?? 'GET'} ${decodeURIComponent(new URL(url).pathname)}`);
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
}

function expectKeyFree(error: unknown): void {
  const e = error as Error & { context?: Record<string, unknown> };
  expect(e.message).not.toContain(SECRET_KEY);
  expect(JSON.stringify(e.context ?? {})).not.toContain(SECRET_KEY);
}

describe('HttpStorageAdapter: the model catalog', () => {
  it('registers a descriptor with POST /v1/models and answers the digest it computed', async () => {
    const platform = fakePlatform();
    const adapter = adapterOver(platform.fetch);
    const d = modelDescriptor();

    const first = await adapter.registerModelDescriptor(d, 'connector-auto', 'wrapper:openai');
    expect(first).toEqual({ digest: modelDigest(d), alreadyExisted: false });
    expect(platform.modelPosts).toEqual([{ descriptor: d, source: 'connector-auto', registeredBy: 'wrapper:openai' }]);

    const again = await adapter.registerModelDescriptor(d, 'connector-auto', 'wrapper:openai');
    expect(again).toEqual({ digest: modelDigest(d), alreadyExisted: true });
  });

  it('sends the bearer key, and no error carries it', async () => {
    const seen: Array<Record<string, string>> = [];
    const fetchFn = (async (_url: string, init: { headers?: Record<string, string> }) => {
      seen.push(init.headers ?? {});
      return new Response(JSON.stringify({ ok: false, error: 'unauthenticated' }), { status: 401 });
    }) as unknown as typeof fetch;
    const adapter = adapterOver(fetchFn);
    const error = await adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli').catch((e: unknown) => e);
    expect(seen[0].Authorization).toBe(`Bearer ${SECRET_KEY}`);
    expect(error).toBeInstanceOf(TzunCatalogError);
    expect(error).toMatchObject({ code: 'unauthenticated', status: 401, operation: 'models.register', retryable: false });
    expectKeyFree(error);
  });

  it('refuses a platform answer naming another digest', async () => {
    const other = 'sha256:' + 'ab'.repeat(32);
    const adapter = adapterOver(answering(201, { ok: true, digest: other, alreadyExisted: false }));
    const error = await adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TzunCatalogError);
    expect(error).toMatchObject({ code: 'digest_mismatch', operation: 'models.register' });
    expect((error as TzunCatalogError).context).toMatchObject({ answeredDigest: other });
  });

  it('applies the integrity invariants before anything is sent', async () => {
    const calls: string[] = [];
    const adapter = adapterOver(answering(201, {}, calls));
    const bad: ModelDescriptor = { ...modelDescriptor(), integrityTier: 'weight-attested', modelDigest: null };
    await expect(adapter.registerModelDescriptor(bad, 'manual', 'cli')).rejects.toThrow(/integrityTier/);
    expect(calls).toEqual([]);
  });

  it('reads a row with GET /v1/models/:digest, takes the descriptor from its canonical bytes, and keeps it', async () => {
    const platform = fakePlatform();
    const adapter = adapterOver(platform.fetch);
    const d = modelDescriptor();
    const { digest } = await adapter.registerModelDescriptor(d, 'connector-auto', 'wrapper:openai');

    const row = await adapter.getModelDescriptor(digest);
    expect(row).toMatchObject({
      modelDescriptorDigest: digest,
      descriptor: d,
      vendor: d.vendor,
      modelName: d.modelName,
      modelVersion: d.modelVersion,
      parentModelDescriptorDigest: null,
      source: 'connector-auto',
      firstRegisteredBy: 'wrapper:openai',
    });
    expect(modelDigest(JSON.parse(row!.canonicalBytes))).toBe(digest);

    // Rows are immutable: the second read is the adapter's, not the platform's.
    await adapter.getModelDescriptor(digest);
    expect(platform.requests.filter((r) => r.startsWith('GET /v1/models/'))).toHaveLength(1);
  });

  it('answers null for a digest the scope does not hold, and asks again next time', async () => {
    const platform = fakePlatform();
    const adapter = adapterOver(platform.fetch);
    const digest = modelDigest(modelDescriptor('never-registered'));
    expect(await adapter.getModelDescriptor(digest)).toBeNull();
    expect(await adapter.getModelDescriptor(digest)).toBeNull();
    expect(platform.requests).toEqual([`GET /v1/models/${digest}`, `GET /v1/models/${digest}`]);
  });

  it('answers null for a reference that is not a descriptor digest, without a request', async () => {
    const calls: string[] = [];
    const adapter = adapterOver(answering(200, {}, calls));
    expect(await adapter.getModelDescriptor('../evidence')).toBeNull();
    expect(await adapter.getModelDescriptor('sha256:XYZ')).toBeNull();
    expect(calls).toEqual([]);
  });

  it('refuses a 2xx row that is not the contract shape, rather than answering null', async () => {
    const adapter = adapterOver(answering(200, { ok: true, canonicalBytes: 42 }));
    const error = await adapter.getModelDescriptor(modelDigest(modelDescriptor())).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TzunCatalogError);
    expect(error).toMatchObject({ code: 'transport_error', operation: 'models.get', retryable: true });
  });

  describe('a platform that does not serve the model catalog', () => {
    afterEach(() => jest.restoreAllMocks());

    it('throws ModelCatalogUnsupportedError on registration, then answers from memory until the re-probe window ends', async () => {
      const platform = fakePlatform({ catalog: false });
      const adapter = adapterOver(platform.fetch);
      let now = 1_000_000;
      jest.spyOn(Date, 'now').mockImplementation(() => now);

      await expect(adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).rejects.toBeInstanceOf(
        ModelCatalogUnsupportedError,
      );
      await expect(adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).rejects.toMatchObject({
        code: 'model_catalog_not_supported_by_store',
      });
      expect(await adapter.getModelDescriptor(modelDigest(modelDescriptor()))).toBeNull();
      expect(platform.requests).toEqual(['POST /v1/models']);

      now += CATALOG_REPROBE_MS;
      await expect(adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).rejects.toBeInstanceOf(
        ModelCatalogUnsupportedError,
      );
      expect(platform.requests).toEqual(['POST /v1/models', 'POST /v1/models']);
    });

    it('reads a 405 or 501 the same way', async () => {
      for (const status of [405, 501]) {
        const adapter = adapterOver(answering(status, {}));
        await expect(adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).rejects.toBeInstanceOf(
          ModelCatalogUnsupportedError,
        );
      }
    });

    it('answers null for a lookup', async () => {
      const adapter = adapterOver(fakePlatform({ catalog: false }).fetch);
      expect(await adapter.getModelDescriptor(modelDigest(modelDescriptor()))).toBeNull();
    });
  });
});

describe('HttpStorageAdapter: the agent catalog', () => {
  it('registers with POST /v1/agents and reads back with GET /v1/agents/:digest', async () => {
    const platform = fakePlatform();
    const adapter = adapterOver(platform.fetch);
    const d = descriptorNamed('claims-triage-agent', 'Example Insurer', 1);
    const digest = agentDescriptorDigest(d);

    expect(await adapter.putAgentDescriptor(d)).toEqual({ digest, alreadyExisted: false });
    expect(await adapter.putAgentDescriptor(d)).toEqual({ digest, alreadyExisted: true });
    const row = await adapter.getAgentDescriptor(digest);
    expect(row).toMatchObject({ digest, name: 'claims-triage-agent', organization: 'Example Insurer', parent: null });
    expect(await adapter.getAgentDescriptor('sha256:' + '00'.repeat(32))).toBeNull();
  });

  it('pages the listing with the decimal cursor the local stores use', async () => {
    const platform = fakePlatform();
    const adapter = adapterOver(platform.fetch);
    for (let i = 0; i < 3; i++) await adapter.putAgentDescriptor(descriptorNamed(`agent-${i}`, 'Example Org', i));
    const first = await adapter.listAgentDescriptors({ limit: 2 });
    expect(first.rows.map((r) => r.name)).toEqual(['agent-0', 'agent-1']);
    expect(first.cursor).toBe('2');
    const second = await adapter.listAgentDescriptors({ limit: 2, cursor: first.cursor! });
    expect(second).toMatchObject({ rows: [{ name: 'agent-2' }], cursor: null });
  });

  it('refuses a descriptor outside the grammar before anything is sent', async () => {
    const platform = fakePlatform();
    const adapter = adapterOver(platform.fetch);
    await expect(adapter.putAgentDescriptor({ v: 'tzun-agent/1' } as never)).rejects.toMatchObject({
      code: 'invalid_agent_descriptor',
    });
    expect(platform.requests).toEqual([]);
  });

  it('a platform without the agent endpoints is a store without the catalog', async () => {
    const platform = fakePlatform({ catalog: false });
    const adapter = adapterOver(platform.fetch);
    const digest = agentDescriptorDigest(policyEngineDescriptor());
    await expect(adapter.getAgentDescriptor(digest)).rejects.toBeInstanceOf(AgentCatalogUnsupportedError);
    await expect(adapter.putAgentDescriptor(policyEngineDescriptor())).rejects.toMatchObject({
      code: 'agent_not_supported_by_store',
    });
    expect(platform.requests).toEqual([`GET /v1/agents/${digest}`, 'GET /v1/agents']);
  });

  it('a platform that serves register and get without the listing refuses the listing only', async () => {
    const platform = fakePlatform({ agentList: false });
    const adapter = adapterOver(platform.fetch);
    const { digest } = await adapter.putAgentDescriptor(policyEngineDescriptor());
    await expect(adapter.listAgentDescriptors()).rejects.toBeInstanceOf(AgentCatalogUnsupportedError);
    expect(await adapter.getAgentDescriptor(digest)).toMatchObject({ digest });
  });
});

describe("the hosted service's spelling: a bare 404 (not_found) for an unregistered digest, rows carrying the descriptor, a digest cursor", () => {
  it('a model lookup is null and leaves registration working', async () => {
    const platform = fakePlatform({ spelling: 'platform' });
    const adapter = adapterOver(platform.fetch);
    expect(await adapter.getModelDescriptor(modelDigest(modelDescriptor('never-registered')))).toBeNull();
    expect(await adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).toMatchObject({ alreadyExisted: false });
  });

  it('an agent lookup is null once the listing shows the catalog is served, and rows carrying the descriptor are read', async () => {
    const platform = fakePlatform({ spelling: 'platform' });
    const adapter = adapterOver(platform.fetch);
    const unregistered = agentDescriptorDigest(descriptorNamed('unregistered', 'Example Org', 9));
    expect(await adapter.getAgentDescriptor(unregistered)).toBeNull();
    expect(platform.requests).toEqual([`GET /v1/agents/${unregistered}`, 'GET /v1/agents']);
    // Known to be served now: no second probe.
    expect(await adapter.getAgentDescriptor(unregistered)).toBeNull();
    expect(platform.requests.filter((r) => r === 'GET /v1/agents')).toHaveLength(1);

    const d = descriptorNamed('claims-triage-agent', 'Example Insurer', 1);
    const { digest } = await adapter.putAgentDescriptor(d);
    const row = await adapter.getAgentDescriptor(digest);
    expect(row).toMatchObject({ digest, name: 'claims-triage-agent', parent: null });
    expect(row!.canonicalBytes).toBe(JSON.stringify(JSON.parse(row!.canonicalBytes)));
    expect((await adapter.listAgentDescriptors()).rows.map((r) => r.digest)).toEqual([digest]);
  });

  it('a bare 404 with no listing either is a platform without the agent catalog', async () => {
    const platform = fakePlatform({ catalog: false });
    const adapter = adapterOver(platform.fetch);
    const digest = agentDescriptorDigest(descriptorNamed('x', 'Example Org', 1));
    await expect(adapter.getAgentDescriptor(digest)).rejects.toBeInstanceOf(AgentCatalogUnsupportedError);
    expect(platform.requests).toEqual([`GET /v1/agents/${digest}`, 'GET /v1/agents']);
  });

  it('capture leaves the reference to the platform, which refuses an unregistered agent', async () => {
    const platform = fakePlatform({ spelling: 'platform' });
    const tzun = await Tzun.init({
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      attestation: { require: [] },
      _httpFetchFn: platform.fetch,
    } as Parameters<typeof Tzun.init>[0]);
    const other = agentDescriptorDigest(descriptorNamed('unregistered', 'Example Org', 9));
    const refused = await tzun.capture({
      aiOutput: { text: 'approve' }, action: 'approved', reason: 'looks right', decider: { kind: 'agent', agent: other },
    } as never);
    expect(refused.stored).toBe(false);
    expect(refused.failure?.failureType).toBe('cloud_invalid_request');
    expect(refused.failure?.diagnosticMetadata).toMatchObject({ reason: 'agent_not_registered', field: 'payload.decider.agent' });
    expect(platform.requests.filter((r) => r.includes('/v1/agents'))).toEqual([]);
    await tzun.close();
  });

  it('tzun.agents.list pages with the digest cursor the platform hands out', async () => {
    const platform = fakePlatform({ spelling: 'platform' });
    const tzun = await cloudTzun(platform);
    const digests: string[] = [];
    for (let i = 0; i < 3; i++) digests.push((await tzun.agents.register(descriptorNamed(`agent-${i}`, 'Example Org', i))).digest);
    const sorted = [...digests].sort();

    const first = await tzun.agents.list({ limit: 2 });
    expect(first.rows.map((r) => r.digest)).toEqual(sorted.slice(0, 2));
    expect(first.cursor).toBe(sorted[1]);
    const second = await tzun.agents.list({ limit: 2, cursor: first.cursor! });
    expect(second).toMatchObject({ rows: [{ digest: sorted[2] }], cursor: null });
    expect(platform.requests).toContain(`GET /v1/agents`);
    await tzun.close();
  });

  it('a cursor the platform refuses is InvalidPaginationError, as on a local store', async () => {
    const platform = fakePlatform({ spelling: 'platform' });
    const tzun = await cloudTzun(platform);
    await expect(tzun.agents.list({ cursor: '2' })).rejects.toMatchObject({ name: 'InvalidPaginationError', field: 'cursor' });
    // Refused before anything is sent: not a cursor any store hands out.
    const before = platform.requests.length;
    await expect(tzun.agents.list({ cursor: 'has space' })).rejects.toMatchObject({ name: 'InvalidPaginationError' });
    await expect(tzun.agents.list({ cursor: '' })).rejects.toMatchObject({ name: 'InvalidPaginationError' });
    expect(platform.requests.length).toBe(before);
    await tzun.close();
  });

  it('takes parent from the descriptor of a row that carries no parent member', async () => {
    const platform = fakePlatform({ spelling: 'platform' });
    const adapter = adapterOver(platform.fetch);
    const base = await adapter.putAgentDescriptor(descriptorNamed('base', 'Example Org', 1));
    const child = { ...descriptorNamed('child', 'Example Org', 2), parent: base.digest, derivation: 'revision' as const };
    const { digest } = await adapter.putAgentDescriptor(child);
    expect(await adapter.getAgentDescriptor(digest)).toMatchObject({ digest, parent: base.digest });
    const listed = await adapter.listAgentDescriptors();
    expect(listed.rows.find((r) => r.digest === digest)).toMatchObject({ parent: base.digest });
  });
});

// ── Through Tzun ──────────────────────────────────────────────────────────

function fakeOpenAI() {
  return {
    chat: {
      completions: {
        create: async (_params: Record<string, unknown>) => ({
          id: 'r1',
          model: 'gpt-4o-2024-08-06',
          choices: [{ message: { content: 'approve' } }],
        }),
      },
    },
  };
}

const DECIDER = { kind: 'human' as const, id: 'acct:u-test' };
const DECISION = { aiOutput: { text: 'approve' }, action: 'approved', reason: 'looks right', decider: DECIDER };

async function cloudTzun(platform: ReturnType<typeof fakePlatform>, events: Array<{ event: string; fields: Record<string, unknown> }> = []) {
  return Tzun.init({
    apiKey: SECRET_KEY,
    apiUrl: API_URL,
    attestation: { require: [] },
    _httpFetchFn: platform.fetch,
    onLog: (event: string, fields: Record<string, unknown>) => events.push({ event, fields }),
  } as Parameters<typeof Tzun.init>[0]);
}

describe('a wrapped vendor call in cloud mode, against a platform that serves the model catalog', () => {
  it('records its model: one contribution step naming the descriptor the platform registered', async () => {
    const platform = fakePlatform();
    const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
    const tzun = await cloudTzun(platform, events);
    const captureSpy = jest.spyOn(tzun, 'capture');
    const client = tzun.attach(fakeOpenAI());

    const response = await client.chat.completions.create({
      model: 'gpt-4o',
      messages: [],
      tzun_capture: { decider: DECIDER, action: 'approved', reason: 'looks right' },
    } as never);
    expect(response).toMatchObject({ id: 'r1' });
    const result = await captureSpy.mock.results[0].value;
    expect(result.stored).toBe(true);

    expect(platform.models.size).toBe(1);
    const [digest] = [...platform.models.keys()];
    expect(platform.evidence).toHaveLength(1);
    const steps = (platform.evidence[0].payload.contributions as { steps: Array<{ aiBom: { modelDescriptorDigest: string } }> }).steps;
    expect(steps).toHaveLength(1);
    expect(steps[0].aiBom.modelDescriptorDigest).toBe(digest);
    expect(events.some((e) => e.event === 'capture_model_not_recordable')).toBe(false);
    expect(events.find((e) => e.event === 'connector_auto_registration')?.fields).toMatchObject({ vendor: 'openai', digest });
    await tzun.close();
  });

  it('a second call reuses the registration and the row: no second POST or GET', async () => {
    const platform = fakePlatform();
    const tzun = await cloudTzun(platform);
    const client = tzun.attach(fakeOpenAI());
    for (let i = 0; i < 2; i++) {
      await client.chat.completions.create({
        model: 'gpt-4o',
        messages: [],
        tzun_capture: { decider: DECIDER, action: 'approved', reason: `call ${i}` },
      } as never);
    }
    expect(platform.evidence).toHaveLength(2);
    expect(platform.requests.filter((r) => r === 'POST /v1/models')).toHaveLength(1);
    expect(platform.requests.filter((r) => r.startsWith('GET /v1/models/'))).toHaveLength(1);
    expect(platform.evidence.every((e) => e.payload.contributions !== null)).toBe(true);
    await tzun.close();
  });

  it('hook() returns the AI-BOM naming the registered digest', async () => {
    const platform = fakePlatform();
    const tzun = await cloudTzun(platform);
    const bom = await tzun.hook('openai', { model: 'gpt-4o' }, { model: 'gpt-4o-2024-08-06' });
    expect(bom).toMatchObject({ modelDescriptorDigest: [...platform.models.keys()][0] });
    await tzun.close();
  });
});

describe('capture() with a step model in cloud mode', () => {
  it('registers an inline step descriptor and records its digest', async () => {
    const platform = fakePlatform();
    const tzun = await cloudTzun(platform);
    const d = modelDescriptor('inline-model');
    const r = await tzun.capture({
      ...DECISION,
      contributions: { steps: [{ role: 'propose', actor: null, aiBom: { modelDescriptor: d, vendorFingerprint: null }, inputs: [], outputOf: { checked: true } }] },
    } as never);
    expect(r.stored).toBe(true);
    const steps = (r.envelope.payload.contributions as { steps: Array<{ aiBom: { modelDescriptorDigest: string } }> }).steps;
    expect(steps[0].aiBom.modelDescriptorDigest).toBe(modelDigest(d));
    expect(platform.models.has(modelDigest(d))).toBe(true);
    await tzun.close();
  });

  it('records a pre-built digest the platform holds, and refuses one it does not hold before anything is sent', async () => {
    const platform = fakePlatform();
    const tzun = await cloudTzun(platform);
    const { digest } = await tzun.models.register(modelDescriptor('prebuilt'));
    const held = await tzun.capture({ ...DECISION, contributions: { steps: [{ role: 'propose', actor: null, aiBom: { modelDescriptorDigest: digest }, inputs: [], outputOf: { checked: true } }] } } as never);
    expect(held.stored).toBe(true);

    const missing = modelDigest(modelDescriptor('never-registered'));
    const refused = await tzun.capture({ ...DECISION, contributions: { steps: [{ role: 'propose', actor: null, aiBom: { modelDescriptorDigest: missing }, inputs: [], outputOf: { checked: true } }] } } as never);
    expect(refused.stored).toBe(false);
    expect(refused.failure?.failureType).toBe('descriptor_not_registered');
    expect(refused.failure?.diagnosticMetadata).toMatchObject({ code: 'descriptor_not_registered' });
    expect(platform.evidence).toHaveLength(1);
    await tzun.close();
  });

  it('a catalog failure while resolving a step model is a cloud failure with its code, and nothing is sent', async () => {
    const platform = fakePlatform();
    const failing = (async (input: string, init?: { method?: string }) => {
      if ((init?.method ?? 'GET') === 'GET' && new URL(input).pathname.startsWith('/v1/models/')) {
        return new Response(JSON.stringify({ ok: false, error: 'store_unavailable' }), { status: 503 });
      }
      return platform.fetch(input, init as RequestInit);
    }) as unknown as typeof fetch;
    const tzun = await Tzun.init({
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      attestation: { require: [] },
      _httpFetchFn: failing,
    } as Parameters<typeof Tzun.init>[0]);
    const digest = modelDigest(modelDescriptor('any'));
    const r = await tzun.capture({ ...DECISION, contributions: { steps: [{ role: 'propose', actor: null, aiBom: { modelDescriptorDigest: digest }, inputs: [], outputOf: { checked: true } }] } } as never);
    expect(r.stored).toBe(false);
    expect(r.failure?.failureType).toBe('cloud_store_unavailable');
    expect(r.failure?.diagnosticMetadata).toMatchObject({ code: 'store_unavailable', status: 503, retryable: true, operation: 'models.get' });
    expect(JSON.stringify(r.failure)).not.toContain(SECRET_KEY);
    expect(platform.evidence).toHaveLength(0);
    await tzun.close();
  });

  it('tzun.models.get reads the platform row', async () => {
    const platform = fakePlatform();
    const tzun = await cloudTzun(platform);
    const { digest } = await tzun.models.register(modelDescriptor('read-me'));
    expect(await tzun.models.get(digest)).toMatchObject({ modelDescriptorDigest: digest, modelName: 'read-me' });
    await tzun.close();
  });
});

describe('agents in cloud mode', () => {
  it('against a platform that serves the agent catalog: register, capture a registered agent, refuse an unregistered one', async () => {
    const platform = fakePlatform();
    const tzun = await cloudTzun(platform);
    const { digest } = await tzun.agents.register(policyEngineDescriptor());
    expect(await tzun.agents.get(digest)).toMatchObject({ digest, name: 'meridian-traffic-generator' });
    expect((await tzun.agents.list()).rows.map((r) => r.digest)).toEqual([digest]);

    const ok = await tzun.capture({ ...DECISION, decider: { kind: 'policy-engine', agent: digest, freshness: null } } as never);
    expect(ok.stored).toBe(true);
    expect(ok.envelope.payload.decider).toMatchObject({ kind: 'policy-engine', agent: digest });

    const other = agentDescriptorDigest(descriptorNamed('unregistered', 'Example Org', 9));
    const refused = await tzun.capture({ ...DECISION, decider: { kind: 'agent', agent: other } } as never);
    expect(refused.stored).toBe(false);
    expect(refused.failure?.diagnosticMetadata).toMatchObject({ reason: 'agent_not_registered', field: 'payload.decider.agent' });

    // A policy engine whose descriptor names a model: the platform's refusal too.
    const modelBearing = (await tzun.agents.register(descriptorNamed('model-bearing', 'Example Org', 3))).digest;
    const mismatch = await tzun.capture({ ...DECISION, decider: { kind: 'policy-engine', agent: modelBearing, freshness: null } } as never);
    expect(mismatch.stored).toBe(false);
    expect(mismatch.failure?.diagnosticMetadata).toMatchObject({ reason: 'agent_kind_mismatch' });

    // Capture read no agent row: the reference check is the platform's.
    expect(platform.requests.filter((r) => r.startsWith('GET /v1/agents/'))).toEqual([`GET /v1/agents/${digest}`]);
    expect(platform.evidence).toHaveLength(1);
    await tzun.close();
  });

  it('against a platform without the agent catalog: references are taken as given, and tzun.agents says the store has none', async () => {
    const platform = fakePlatform({ catalog: false });
    const tzun = await cloudTzun(platform);
    const digest = agentDescriptorDigest(descriptorNamed('unregistered', 'Example Org', 9));
    const r = await tzun.capture({ ...DECISION, decider: { kind: 'agent', agent: digest } } as never);
    expect(r.stored).toBe(true);
    await expect(tzun.agents.register(policyEngineDescriptor())).rejects.toMatchObject({ code: 'agent_not_supported_by_store' });
    await expect(tzun.agents.get(digest)).rejects.toMatchObject({ code: 'agent_not_supported_by_store' });
    await tzun.close();
  });
});

// ── What the platform may answer that is not the contract ─────────────────

/** A fetch that answers from `serving` until `rollBack()`, then from a platform without the catalog. */
function rollingBack(serving: ReturnType<typeof fakePlatform>) {
  const older = fakePlatform({ catalog: false });
  let current = serving;
  return {
    fetch: ((input: string, init?: RequestInit) => current.fetch(input, init)) as unknown as typeof fetch,
    rollBack: () => {
      current = older;
    },
    older,
  };
}

function htmlNotFoundOnce(platform: ReturnType<typeof fakePlatform>, method: string, path: string): typeof fetch {
  let sent = false;
  return (async (input: string, init?: { method?: string }) => {
    if (!sent && (init?.method ?? 'GET') === method && decodeURIComponent(new URL(input).pathname) === path) {
      sent = true;
      return new Response('<html><body>Application not found</body></html>', {
        status: 404,
        headers: { 'Content-Type': 'text/html' },
      });
    }
    return platform.fetch(input, init as RequestInit);
  }) as unknown as typeof fetch;
}

describe('a platform rolled back to a build without the agent catalog', () => {
  afterEach(() => jest.restoreAllMocks());

  it('is noticed once the served answer is older than the re-probe window', async () => {
    let now = 1_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const serving = fakePlatform({ spelling: 'platform' });
    const platform = rollingBack(serving);
    const adapter = adapterOver(platform.fetch);
    const unregistered = agentDescriptorDigest(descriptorNamed('unregistered', 'Example Org', 9));
    await adapter.putAgentDescriptor(policyEngineDescriptor());
    expect(await adapter.getAgentDescriptor(unregistered)).toBeNull();

    platform.rollBack();
    now += CATALOG_REPROBE_MS;
    await expect(adapter.getAgentDescriptor(unregistered)).rejects.toBeInstanceOf(AgentCatalogUnsupportedError);
    expect(platform.older.requests).toEqual([`GET /v1/agents/${unregistered}`, 'GET /v1/agents']);
  });

  it('capture keeps storing records: it never reads the agent catalog in cloud mode', async () => {
    const serving = fakePlatform();
    const platform = rollingBack(serving);
    const tzun = await Tzun.init({
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      attestation: { require: [] },
      _httpFetchFn: platform.fetch,
    } as Parameters<typeof Tzun.init>[0]);
    const { digest } = await tzun.agents.register(policyEngineDescriptor());
    expect((await tzun.capture({ ...DECISION, decider: { kind: 'policy-engine', agent: digest, freshness: null } } as never)).stored).toBe(true);

    platform.rollBack();
    const other = agentDescriptorDigest(descriptorNamed('unregistered', 'Example Org', 9));
    const r = await tzun.capture({ ...DECISION, decider: { kind: 'agent', agent: other } } as never);
    expect(r.stored).toBe(true);
    expect(platform.older.evidence).toHaveLength(1);
    expect(platform.older.requests).toEqual(['POST /v1/evidence']);
    await tzun.close();
  });
});

describe('a 404 that is not the platform catch-all', () => {
  it('an HTML 404 on POST /v1/models is a retryable transport error and does not switch model recording off', async () => {
    const platform = fakePlatform();
    const adapter = adapterOver(htmlNotFoundOnce(platform, 'POST', '/v1/models'));
    const error = await adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TzunCatalogError);
    expect(error).toMatchObject({ code: 'transport_error', status: 404, retryable: true, operation: 'models.register' });
    expect(adapter.modelCatalogKnownAbsent()).toBe(false);
    expect(await adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).toMatchObject({ alreadyExisted: false });
  });

  it('a wrapped call during the deploy loses only its own model; the next call records it', async () => {
    const platform = fakePlatform();
    const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
    const tzun = await Tzun.init({
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      attestation: { require: [] },
      _httpFetchFn: htmlNotFoundOnce(platform, 'POST', '/v1/models'),
      onLog: (event: string, fields: Record<string, unknown>) => events.push({ event, fields }),
    } as Parameters<typeof Tzun.init>[0]);
    const client = tzun.attach(fakeOpenAI());
    for (let i = 0; i < 2; i++) {
      await client.chat.completions.create({
        model: 'gpt-4o',
        messages: [],
        tzun_capture: { decider: DECIDER, action: 'approved', reason: `call ${i}` },
      } as never);
    }
    expect(platform.evidence).toHaveLength(2);
    expect(platform.evidence[0].payload.contributions).toBeNull();
    expect(platform.evidence[1].payload.contributions).not.toBeNull();
    expect(events.find((e) => e.event === 'connector_hook_failure')?.fields).toMatchObject({ vendor: 'openai', errorName: 'TzunCatalogError' });
    expect(events.some((e) => e.event === 'capture_model_not_recordable')).toBe(false);
    await tzun.close();
  });

  it('an HTML 404 on an agent lookup is a retryable transport error, not "no catalog"', async () => {
    const platform = fakePlatform();
    const digest = agentDescriptorDigest(policyEngineDescriptor());
    const adapter = adapterOver(htmlNotFoundOnce(platform, 'GET', `/v1/agents/${digest}`));
    await adapter.putAgentDescriptor(policyEngineDescriptor());
    await expect(adapter.getAgentDescriptor(digest)).rejects.toMatchObject({ code: 'transport_error', retryable: true });
    expect(await adapter.getAgentDescriptor(digest)).toMatchObject({ digest });
  });

  it('a JSON 404 with a code the route does not use on a write is retryable, and decides nothing', async () => {
    const calls: string[] = [];
    const adapter = adapterOver(answering(404, { ok: false, error: 'descriptor_not_registered' }, calls));
    await expect(adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).rejects.toMatchObject({
      code: 'transport_error',
      retryable: true,
      context: { error: 'descriptor_not_registered' },
    });
    await expect(adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).rejects.toBeInstanceOf(TzunCatalogError);
    expect(calls).toEqual(['POST /v1/models', 'POST /v1/models']);
  });

  it('a 403 is forbidden, not a transport error', async () => {
    const adapter = adapterOver(answering(403, { ok: false }));
    await expect(adapter.registerModelDescriptor(modelDescriptor(), 'manual', 'cli')).rejects.toMatchObject({
      code: 'forbidden',
      status: 403,
      retryable: false,
    });
  });
});

describe('rows the platform answers are re-hashed', () => {
  function rowServing(body: Record<string, unknown>, calls: string[] = []): typeof fetch {
    return answering(200, body, calls);
  }

  it('a model row whose bytes do not hash to the digest is refused and not kept', async () => {
    const asked = modelDigest(modelDescriptor('asked-for'));
    const calls: string[] = [];
    const adapter = adapterOver(
      rowServing({ ok: true, modelDescriptorDigest: asked, canonicalBytes: JSON.stringify(modelDescriptor('another')) }, calls),
    );
    await expect(adapter.getModelDescriptor(asked)).rejects.toMatchObject({ code: 'digest_mismatch', operation: 'models.get' });
    await expect(adapter.getModelDescriptor(asked)).rejects.toMatchObject({ code: 'digest_mismatch' });
    expect(calls).toHaveLength(2);
  });

  it("an agent row for another digest is refused, by its digest member or by its bytes", async () => {
    const a = descriptorNamed('a', 'Example Org', 1);
    const b = descriptorNamed('b', 'Example Org', 2);
    const digestA = agentDescriptorDigest(a);
    const digestB = agentDescriptorDigest(b);
    const row = (digest: string, d: typeof a) => ({
      ok: true,
      digest,
      canonicalBytes: canonicalSerializeAgentDescriptor(d),
      name: d.name,
      organization: d.operator.organization,
      parent: null,
      registeredAt: '2026-10-07T12:00:00.000Z',
    });
    // B's row answered for A.
    await expect(adapterOver(rowServing(row(digestB, b))).getAgentDescriptor(digestA)).rejects.toMatchObject({
      code: 'transport_error',
      operation: 'agents.get',
    });
    // A row that names A but holds B's bytes.
    await expect(adapterOver(rowServing(row(digestA, b))).getAgentDescriptor(digestA)).rejects.toMatchObject({
      code: 'digest_mismatch',
      operation: 'agents.get',
    });
  });

  it('an agent registration answered with another digest is refused', async () => {
    const other = 'sha256:' + 'cd'.repeat(32);
    const adapter = adapterOver(answering(201, { ok: true, digest: other, alreadyExisted: false }));
    const error = await adapter.putAgentDescriptor(policyEngineDescriptor()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TzunCatalogError);
    expect(error).toMatchObject({ code: 'digest_mismatch', operation: 'agents.register', context: { answeredDigest: other } });
  });
});

describe('a pre-built step digest on a platform known to have no model catalog', () => {
  it('is refused as a digest this store cannot check, not one to register first', async () => {
    const platform = fakePlatform({ catalog: false });
    const tzun = await cloudTzun(platform);
    // A wrapped call or tzun.models.register has met the older platform.
    await expect(tzun.models.register(modelDescriptor())).rejects.toBeDefined();
    const digest = modelDigest(modelDescriptor());
    const r = await tzun.capture({ ...DECISION, contributions: { steps: [{ role: 'propose', actor: null, aiBom: { modelDescriptorDigest: digest }, inputs: [], outputOf: { checked: true } }] } } as never);
    expect(r.stored).toBe(false);
    expect(r.failure?.failureType).toBe('descriptor_not_registered');
    expect(String(r.failure?.diagnosticMetadata.message)).toMatch(/cannot check .* the platform does not serve the model catalog/);

    // On a serving platform the same miss names the remedies.
    const serving = await cloudTzun(fakePlatform());
    const missed = await serving.capture({ ...DECISION, contributions: { steps: [{ role: 'propose', actor: null, aiBom: { modelDescriptorDigest: digest }, inputs: [], outputOf: { checked: true } }] } } as never);
    expect(String(missed.failure?.diagnosticMetadata.message)).toMatch(/register the descriptor before capture/);
    await serving.close();
    await tzun.close();
  });
});
