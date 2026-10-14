/**
 * The agent catalog's capture hook and export helpers (src/sdk/agents)
 * against stand-in stores:
 *
 *   - capture and store-level verification agree on every catalog row: what
 *     capture accepts verification resolves, and what capture refuses
 *     verification reports unresolved, for the same reason;
 *   - a store that answers `agent_not_supported_by_store` (the cloud
 *     transport) is a store without the catalog;
 *   - an export bundles every referenced descriptor's row verbatim, marks a
 *     gap as missing, and reads back into the same verdict offline.
 */
import { canonicalSerialize, canonicalSerializeAgentDescriptor, verifyEnvelope } from '@tzun/engine';
import type { AgentDescriptor, AgentDescriptorRow, EvidenceEnvelope, StorageAdapter, TzunConfig } from '@tzun/engine';
import { Tzun } from '../../../src/sdk';
import type { AgentReference, SdkHost } from '../../../src/sdk/extension-points';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import {
  AgentCatalogUnsupportedError,
  agentCaptureHook,
  agentsApi,
  agentsSdkExtension,
  agentsStorageExtension,
  exportAgentDescriptors,
  exportedAgentCatalog,
  recordAgentReferences,
  resolveAgentDescriptor,
} from '../../../src/sdk/agents';
import { prefixedSha256 } from '../../../src/storage/agent-sql';
import { X12, policyEngineDescriptor } from './fixtures';

const decision = { aiOutput: { recommendation: 'pay' }, action: 'pay', reason: 'within the automatic-payment limit' };
const X12_BYTES = canonicalSerializeAgentDescriptor(X12);
/** The canonical bytes of any object. */
const canonicalOf = (value: Record<string, unknown>): string => canonicalSerialize(value, Object.keys(value));
const X12_DIGEST = prefixedSha256(X12_BYTES);

function rowOf(digest: string, canonicalBytes: string): AgentDescriptorRow {
  return { digest, canonicalBytes, name: 'n', organization: 'o', parent: null, registeredAt: '2026-10-01T00:00:00.000Z' };
}

/** A store whose catalog answers `rows` (by digest) and nothing else. */
function catalogStore(rows: Record<string, AgentDescriptorRow>): Pick<StorageAdapter, 'getAgentDescriptor'> & { reads: string[] } {
  const reads: string[] = [];
  return {
    reads,
    async getAgentDescriptor(digest: string) {
      reads.push(digest);
      return rows[digest] ?? null;
    },
  };
}

function hostOver(storage: object): SdkHost {
  return { storage, log: () => undefined } as unknown as SdkHost;
}

/** Records by digest, captured in a store without the catalog (which accepts any reference). */
async function recordsNaming(refs: Array<{ kind: 'agent' | 'policy-engine'; agent: string }>): Promise<EvidenceEnvelope[]> {
  const tzun = await Tzun.init({ mode: 'dev', _storageExtensions: [decidersExtension] } as TzunConfig);
  try {
    const out: EvidenceEnvelope[] = [];
    for (const decider of refs) {
      const r = await tzun.capture({ ...decision, decider });
      expect(r.failure).toBeUndefined();
      out.push(r.envelope);
    }
    return out;
  } finally {
    await tzun.close();
  }
}

describe('capture and store-level verification agree on each catalog row', () => {
  const notJson = 'not a descriptor';
  const spaced = JSON.stringify(JSON.parse(X12_BYTES), null, 1);
  const extra = canonicalOf({ ...X12, extra: true });
  const cases: Array<{
    label: string;
    kind: 'agent' | 'policy-engine';
    agent: string;
    rows: Record<string, AgentDescriptorRow>;
    capture: null | { code: string; catalog?: string };
    verify: { resolved: boolean; reason?: string };
  }> = [
    { label: 'a registered descriptor', kind: 'agent', agent: X12_DIGEST, rows: { [X12_DIGEST]: rowOf(X12_DIGEST, X12_BYTES) }, capture: null, verify: { resolved: true } },
    { label: 'no row', kind: 'agent', agent: X12_DIGEST, rows: {}, capture: { code: 'agent_not_registered' }, verify: { resolved: false, reason: 'not_registered' } },
    {
      label: 'bytes that do not hash to the reference',
      kind: 'agent',
      agent: X12_DIGEST,
      rows: { [X12_DIGEST]: rowOf(X12_DIGEST, X12_BYTES.replace('claims-triage-agent', 'claims-triage-agenT')) },
      capture: { code: 'agent_not_registered', catalog: 'digest_mismatch' },
      verify: { resolved: false, reason: 'digest_mismatch' },
    },
    {
      label: 'bytes that are not JSON',
      kind: 'agent',
      agent: prefixedSha256(notJson),
      rows: { [prefixedSha256(notJson)]: rowOf(prefixedSha256(notJson), notJson) },
      capture: { code: 'agent_not_registered', catalog: 'malformed_descriptor' },
      verify: { resolved: false, reason: 'malformed_descriptor' },
    },
    {
      label: 'a descriptor not in canonical form',
      kind: 'agent',
      agent: prefixedSha256(spaced),
      rows: { [prefixedSha256(spaced)]: rowOf(prefixedSha256(spaced), spaced) },
      capture: { code: 'agent_not_registered', catalog: 'malformed_descriptor' },
      verify: { resolved: false, reason: 'malformed_descriptor' },
    },
    {
      label: 'canonical bytes that are not a descriptor',
      kind: 'agent',
      agent: prefixedSha256(extra),
      rows: { [prefixedSha256(extra)]: rowOf(prefixedSha256(extra), extra) },
      capture: { code: 'agent_not_registered', catalog: 'malformed_descriptor' },
      verify: { resolved: false, reason: 'malformed_descriptor' },
    },
    {
      label: 'a policy engine whose descriptor names a model',
      kind: 'policy-engine',
      agent: X12_DIGEST,
      rows: { [X12_DIGEST]: rowOf(X12_DIGEST, X12_BYTES) },
      capture: { code: 'agent_kind_mismatch' },
      verify: { resolved: false, reason: 'agent_kind_mismatch' },
    },
  ];

  let envelopes: EvidenceEnvelope[];
  beforeAll(async () => {
    envelopes = await recordsNaming(cases.map(({ kind, agent }) => ({ kind, agent })));
  });

  it.each(cases.map((c, i) => [c.label, i] as const))('%s', async (_label, i) => {
    const c = cases[i];
    const storage = catalogStore(c.rows);
    const ref: AgentReference = { field: 'decider.agent', kind: c.kind, agent: c.agent };
    const refused = await agentCaptureHook().checkReferences([ref], { host: hostOver(storage) });
    if (c.capture === null) {
      expect(refused).toBeNull();
    } else {
      expect(refused).toMatchObject({ failureType: 'validation_failure', code: c.capture.code, field: 'decider.agent' });
      expect(refused?.details?.catalog).toBe(c.capture.catalog);
    }
    const verified = await verifyEnvelope(envelopes[i], undefined, undefined, { storage: storage as unknown as StorageAdapter });
    expect(verified.agents).toEqual([{ reference: c.agent, field: 'decider', ...c.verify }]);
  });
});

describe('the capture hook', () => {
  const ref = (agent: string, field = 'decider.agent', kind: AgentReference['kind'] = 'agent'): AgentReference => ({ field, kind, agent });

  it('reads nothing for a record that names no agent', async () => {
    const storage = catalogStore({});
    expect(await agentCaptureHook().checkReferences([], { host: hostOver(storage) })).toBeNull();
    expect(storage.reads).toEqual([]);
  });

  it('accepts every reference in a store without the catalog, or one that answers agent_not_supported_by_store', async () => {
    expect(await agentCaptureHook().checkReferences([ref(X12_DIGEST)], { host: hostOver({}) })).toBeNull();
    const cloud = {
      async getAgentDescriptor(): Promise<never> {
        throw Object.assign(new Error('the platform does not serve its catalog yet'), { code: 'agent_not_supported_by_store' });
      },
    };
    expect(await agentCaptureHook().checkReferences([ref(X12_DIGEST)], { host: hostOver(cloud) })).toBeNull();
  });

  it('lets any other store failure through', async () => {
    const broken = {
      async getAgentDescriptor(): Promise<never> {
        throw new Error('connection reset');
      },
    };
    await expect(agentCaptureHook().checkReferences([ref(X12_DIGEST)], { host: hostOver(broken) })).rejects.toThrow('connection reset');
  });

  it('reads a digest named twice once, and the first failing reference decides', async () => {
    const engine = policyEngineDescriptor();
    const engineBytes = canonicalSerializeAgentDescriptor(engine);
    const engineDigest = prefixedSha256(engineBytes);
    const storage = catalogStore({ [X12_DIGEST]: rowOf(X12_DIGEST, X12_BYTES), [engineDigest]: rowOf(engineDigest, engineBytes) });
    const refs = [
      ref(engineDigest, 'decider.agent', 'policy-engine'),
      ref(X12_DIGEST, 'contributions.steps[0].actor.agent'),
      ref(X12_DIGEST, 'contributions.steps[1].actor.agent', 'policy-engine'),
      ref(`sha256:${'00'.repeat(32)}`, 'contributions.steps[2].actor.agent'),
    ];
    const refused = await agentCaptureHook().checkReferences(refs, { host: hostOver(storage) });
    expect(refused).toMatchObject({ code: 'agent_kind_mismatch', field: 'contributions.steps[1].actor.agent' });
    expect(storage.reads).toEqual([engineDigest, X12_DIGEST]);
  });
});

describe('the namespace over a store that answers agent_not_supported_by_store', () => {
  it('refuses with AgentCatalogUnsupportedError', async () => {
    const unsupported = async (): Promise<never> => {
      throw Object.assign(new Error('not yet'), { code: 'agent_not_supported_by_store' });
    };
    const api = agentsApi(hostOver({ putAgentDescriptor: unsupported, getAgentDescriptor: unsupported, listAgentDescriptors: unsupported }));
    await expect(api.register(X12)).rejects.toBeInstanceOf(AgentCatalogUnsupportedError);
    await expect(api.get(X12_DIGEST)).rejects.toBeInstanceOf(AgentCatalogUnsupportedError);
    await expect(api.list()).rejects.toBeInstanceOf(AgentCatalogUnsupportedError);
  });
});

describe('tzun.agents.register', () => {
  it('reads the descriptor once and hands the store the copy it checked', async () => {
    const handed: unknown[] = [];
    const api = agentsApi(
      hostOver({
        async putAgentDescriptor(d: unknown) {
          handed.push(d);
          return { digest: X12_DIGEST, alreadyExisted: false };
        },
      }),
    );
    let reads = 0;
    const shifting = { ...X12 } as Record<string, unknown>;
    Object.defineProperty(shifting, 'name', { enumerable: true, get: () => (++reads > 1 ? 'x'.repeat(5000) : X12.name) });
    await api.register(shifting as unknown as AgentDescriptor);
    expect(reads).toBe(1);
    expect(handed).toEqual([X12]);
    expect(handed[0]).not.toBe(shifting);
    expect(Object.getOwnPropertyDescriptor(handed[0], 'name')).toMatchObject({ value: X12.name });
  });

  it('refuses a descriptor with a hole or U+0000 with invalid_agent_descriptor, before the store is reached', async () => {
    const handed: unknown[] = [];
    const api = agentsApi(hostOver({ putAgentDescriptor: async (d: unknown) => (handed.push(d), { digest: X12_DIGEST, alreadyExisted: false }) }));
    const sparse: string[] = [];
    sparse[1] = 'spiffe://a/1';
    for (const bad of [{ ...X12, identities: sparse }, { ...X12, name: 'a\u0000b' }, { ...X12, operator: { ...X12.operator, organization: '\u0000' } }]) {
      await expect(api.register(bad as AgentDescriptor)).rejects.toMatchObject({ code: 'invalid_agent_descriptor', field: 'descriptor' });
    }
    expect(handed).toEqual([]);
  });
});

describe('resolveAgentDescriptor', () => {
  it('names the state a reference is in', async () => {
    expect(await resolveAgentDescriptor({}, X12_DIGEST)).toEqual({ state: 'catalog_absent' });
    expect(await resolveAgentDescriptor(catalogStore({}), X12_DIGEST)).toEqual({ state: 'not_registered' });
    const resolved = await resolveAgentDescriptor(catalogStore({ [X12_DIGEST]: rowOf(X12_DIGEST, X12_BYTES) }), X12_DIGEST);
    expect(resolved).toMatchObject({ state: 'resolved', descriptor: X12 });
  });
});

describe('export: resolvedAgentDescriptors', () => {
  it('bundles each referenced row once, verbatim, and reads back into the store verdict offline', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      _sdkExtensions: [agentsSdkExtension],
      _storageExtensions: [decidersExtension, agentsStorageExtension],
    } as TzunConfig);
    try {
      const engine = (await tzun.agents.register(policyEngineDescriptor())).digest;
      const model = (await tzun.agents.register(X12)).digest;
      const actor = { role: 'other', actor: { kind: 'agent' as const, agent: model }, aiBom: null, inputs: [], outputOf: { n: 1 } };
      const r = await tzun.capture({
        ...decision,
        decider: { kind: 'policy-engine', agent: engine },
        contributions: { steps: [actor, { ...actor, outputOf: { n: 2 } }] },
      });
      expect(r.failure).toBeUndefined();
      const envelope = r.envelope;
      expect(recordAgentReferences(envelope).map((x) => x.field)).toEqual(['decider', 'contributions.steps[0].actor', 'contributions.steps[1].actor']);

      const entries = await exportAgentDescriptors(envelope, tzun.getStorage());
      expect(Object.keys(entries)).toEqual([engine, model]);
      expect(entries[model]).toEqual({
        canonicalBytes: X12_BYTES,
        name: 'claims-triage-agent',
        organization: 'Example Insurer',
        parent: null,
        registeredAt: expect.stringMatching(/Z$/),
      });

      const offline = async (bundled: typeof entries) =>
        (await verifyEnvelope(envelope, undefined, undefined, { storage: exportedAgentCatalog(bundled) as StorageAdapter })).agents;
      const stored = (await tzun.verify(envelope.payload.evidenceId)).agents;
      expect(await offline(entries)).toEqual(stored);
      expect(stored!.every((a) => a.resolved)).toBe(true);

      // A row rewritten in the bundle, and one left out, are reported, never passed.
      const rewritten = { ...entries, [model]: { ...entries[model], canonicalBytes: X12_BYTES.replace('Example', 'Other') } } as typeof entries;
      expect((await offline(rewritten))!.map((a) => a.reason ?? 'resolved')).toEqual(['resolved', 'digest_mismatch', 'digest_mismatch']);
      const { [model]: _dropped, ...partial } = entries;
      expect((await offline(partial))!.map((a) => a.reason ?? 'resolved')).toEqual(['resolved', 'not_registered', 'not_registered']);
      // JSON round trip: the bundle travels as JSON.
      expect(await offline(JSON.parse(JSON.stringify(entries)))).toEqual(stored);
    } finally {
      await tzun.close();
    }
  });

  it('marks every reference missing when the store keeps no catalog, and one the catalog does not hold', async () => {
    const [envelope] = await recordsNaming([{ kind: 'agent', agent: X12_DIGEST }]);
    const absent = await exportAgentDescriptors(envelope, {});
    expect(absent).toEqual({ [X12_DIGEST]: { canonicalBytes: '', missing: true, reason: 'catalog_absent' } });
    const cloud = {
      async getAgentDescriptor(): Promise<never> {
        throw Object.assign(new Error('not yet'), { code: 'agent_not_supported_by_store' });
      },
    };
    expect(await exportAgentDescriptors(envelope, cloud)).toEqual(absent);
    const verdict = await verifyEnvelope(envelope, undefined, undefined, { storage: exportedAgentCatalog(absent) as StorageAdapter });
    expect(verdict.agents).toEqual([{ reference: X12_DIGEST, field: 'decider', resolved: false, reason: 'catalog_absent' }]);

    const unregistered = await exportAgentDescriptors(envelope, catalogStore({}));
    expect(unregistered).toEqual({ [X12_DIGEST]: { canonicalBytes: '', missing: true, reason: 'not_registered' } });
  });

  it('reads each reference from its own entry when not every entry is catalog_absent', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      _sdkExtensions: [agentsSdkExtension],
      _storageExtensions: [decidersExtension, agentsStorageExtension],
    } as TzunConfig);
    try {
      const { digest } = await tzun.agents.register(X12);
      const r = await tzun.capture({ ...decision, decider: { kind: 'agent', agent: digest } });
      expect(r.failure).toBeUndefined();
      const entries = JSON.parse(JSON.stringify(await exportAgentDescriptors(r.envelope, tzun.getStorage())));
      entries[digest].canonicalBytes = entries[digest].canonicalBytes.replace('claims', 'other');
      const reasons = async (bundled: Record<string, unknown>) =>
        (await verifyEnvelope(r.envelope, undefined, undefined, { storage: exportedAgentCatalog(bundled as never) as StorageAdapter })).agents!.map(
          (a) => a.reason,
        );
      expect(await reasons(entries)).toEqual(['digest_mismatch']);
      // A catalog_absent entry under a digest the record does not name does not relabel the rewritten row.
      const junk = { ...entries, [`sha256:${'f'.repeat(64)}`]: { canonicalBytes: '', missing: true, reason: 'catalog_absent' } };
      expect(await reasons(junk)).toEqual(['digest_mismatch']);
      // Nor does it stand in for the record's own entry: a reference read from a catalog_absent entry among others is not registered.
      const mixed = { ...junk, [digest]: { canonicalBytes: '', missing: true, reason: 'catalog_absent' }, [`sha256:${'e'.repeat(64)}`]: entries[digest] };
      expect(await reasons(mixed)).toEqual(['not_registered']);
    } finally {
      await tzun.close();
    }
  });

  it('reads a malformed bundle as unregistered, never throwing', async () => {
    const [envelope] = await recordsNaming([{ kind: 'agent', agent: X12_DIGEST }]);
    for (const bundled of [null, undefined, 7, [], { [X12_DIGEST]: null }, { [X12_DIGEST]: { canonicalBytes: 7 } }]) {
      const catalog = exportedAgentCatalog(bundled as never);
      const verdict = await verifyEnvelope(envelope, undefined, undefined, { storage: catalog as StorageAdapter });
      expect(verdict.agents).toEqual([{ reference: X12_DIGEST, field: 'decider', resolved: false, reason: 'not_registered' }]);
    }
    expect(recordAgentReferences(null as unknown as EvidenceEnvelope)).toEqual([]);
    expect(recordAgentReferences({ payload: { decider: 'x', contributions: { steps: [null, { actor: 7 }] } } } as unknown as EvidenceEnvelope)).toEqual([]);
  });
});
