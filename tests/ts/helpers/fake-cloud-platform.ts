/**
 * A fake of the platform's key-authenticated API for the cloud transport
 * suites: `POST /v1/evidence` and, unless `catalog: false`, the model and
 * agent catalog endpoints of the SDK 0.8.0 cloud catalog contract.
 *
 *   POST /v1/models          { descriptor, source?, registeredBy? }
 *                            -> 201 | 200 { ok, digest, alreadyExisted }
 *   GET  /v1/models/:digest  -> 200 { ok, ...ModelDescriptorRow }
 *                            |  404 { ok:false, error:'descriptor_not_registered' }
 *   POST /v1/agents          { descriptor } -> 201 | 200 { ok, digest, alreadyExisted }
 *   GET  /v1/agents/:digest  -> 200 { ok, ...AgentDescriptorRow }
 *                            |  404 { ok:false, error:'agent_not_registered' }
 *   GET  /v1/agents?…        -> 200 { ok, rows, cursor }   (unless `agentList: false`)
 *
 * With the catalog, `POST /v1/evidence` refuses an agent reference the
 * catalog does not hold, or a `policy-engine` agent whose descriptor names a
 * model, as the platform does: `400 { ok:false, error:'invalid_request',
 * reason:'agent_not_registered' | 'agent_kind_mismatch', field }`.
 *
 * Every other request answers as the platform's catch-all does:
 * 404 { ok:false, error:'not_found' }. With `catalog: false` the fake is a
 * platform that predates the catalog endpoints.
 */
import { createHash } from 'node:crypto';
import {
  canonicalSerializeAgentDescriptor,
  canonicalSerializeDescriptor,
  type AgentDescriptor,
  type EvidenceEnvelope,
  type ModelDescriptor,
} from '@tzun/engine';

export interface FakePlatformOptions {
  /** `false`: a platform without the catalog endpoints. Default `true`. */
  catalog?: boolean;
  /** `false`: the agent catalog without `GET /v1/agents`. Default `true`. */
  agentList?: boolean;
  /**
   * `'platform'`: what the hosted service's catalog routes answer. The
   * catalog answers an unregistered digest with
   * the catch-all's `not_found`, an agent row with its parsed `descriptor` in
   * place of `canonicalBytes` and `parent`, and a listing as
   * `{ agents, nextCursor }` ordered by digest, whose cursor is the last
   * row's digest; a cursor that is not a digest is
   * `400 { error:'invalid_request', field:'cursor' }`. Default `'contract'`.
   */
  spelling?: 'contract' | 'platform';
}

export interface FakePlatform {
  fetch: typeof fetch;
  /** Every request, as `METHOD path` (the path decoded). */
  requests: string[];
  /** The envelopes `POST /v1/evidence` stored. */
  evidence: EvidenceEnvelope[];
  /** The bodies `POST /v1/models` was sent. */
  modelPosts: Array<Record<string, unknown>>;
  /** The model catalog, by digest. */
  models: Map<string, { canonicalBytes: string; source: string; registeredBy: string; at: string }>;
  /** The agent catalog, by digest. */
  agents: Map<string, { canonicalBytes: string; name: string; organization: string; parent: string | null; at: string }>;
}

const sha = (text: string): string => 'sha256:' + createHash('sha256').update(text, 'utf8').digest('hex');

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/** A fake platform; `fetch` is what `_httpFetchFn` / `fetchFn` takes. */
export function fakePlatform(options: FakePlatformOptions = {}): FakePlatform {
  const catalog = options.catalog !== false;
  const agentList = options.agentList !== false;
  const bare = options.spelling === 'platform';
  const state: FakePlatform = {
    fetch: undefined as unknown as typeof fetch,
    requests: [],
    evidence: [],
    modelPosts: [],
    models: new Map(),
    agents: new Map(),
  };
  const notFound = () => json(404, { ok: false, error: 'not_found' });

  state.fetch = (async (input: string, init: { method?: string; body?: string } = {}) => {
    const url = new URL(input);
    const method = (init.method ?? 'GET').toUpperCase();
    const path = decodeURIComponent(url.pathname);
    state.requests.push(`${method} ${path}`);
    const body = init.body !== undefined ? (JSON.parse(String(init.body)) as Record<string, unknown>) : null;

    if (method === 'POST' && path === '/v1/evidence') {
      const envelope = body!.envelope as EvidenceEnvelope;
      const refused = catalog ? agentRefusal(envelope, state.agents) : null;
      if (refused !== null) return json(400, { ok: false, error: 'invalid_request', ...refused });
      state.evidence.push(envelope);
      return json(202, {
        ok: true,
        state: 'captured',
        evidenceId: envelope.payload.evidenceId,
        chainId: (body!.chainId as string | undefined) ?? 'default',
        sequence: envelope.payload.sequenceNumber,
        canonicalDigest: envelope.integrity.canonicalDigest,
        headDigest: envelope.integrity.canonicalDigest,
      });
    }
    if (!catalog) return notFound();

    if (method === 'POST' && path === '/v1/models') {
      state.modelPosts.push(body!);
      const descriptor = body!.descriptor as ModelDescriptor;
      const canonicalBytes = canonicalSerializeDescriptor(descriptor);
      const digest = sha(canonicalBytes);
      const existed = state.models.has(digest);
      if (!existed) {
        state.models.set(digest, {
          canonicalBytes,
          source: (body!.source as string | undefined) ?? 'manual',
          registeredBy: (body!.registeredBy as string | undefined) ?? '',
          at: '2026-10-07T12:00:00.000Z',
        });
      }
      return json(existed ? 200 : 201, { ok: true, digest, alreadyExisted: existed });
    }
    const model = /^\/v1\/models\/(sha256:[0-9a-f]{64})$/.exec(path);
    if (method === 'GET' && model) {
      const row = state.models.get(model[1]);
      if (!row) return json(404, { ok: false, error: bare ? 'not_found' : 'descriptor_not_registered' });
      const d = JSON.parse(row.canonicalBytes) as ModelDescriptor;
      return json(200, {
        ok: true,
        modelDescriptorDigest: model[1],
        canonicalBytes: row.canonicalBytes,
        descriptor: d,
        vendor: d.vendor,
        modelName: d.modelName,
        modelVersion: d.modelVersion,
        parentModelDescriptorDigest: d.parentModelDescriptorDigest,
        source: row.source,
        firstRegisteredAt: row.at,
        firstRegisteredBy: row.registeredBy,
      });
    }

    if (method === 'POST' && path === '/v1/agents') {
      const descriptor = body!.descriptor as AgentDescriptor;
      const canonicalBytes = canonicalSerializeAgentDescriptor(descriptor);
      const digest = sha(canonicalBytes);
      const existed = state.agents.has(digest);
      if (!existed) {
        state.agents.set(digest, {
          canonicalBytes,
          name: descriptor.name,
          organization: descriptor.operator.organization,
          parent: descriptor.parent,
          at: '2026-10-07T12:00:00.000Z',
        });
      }
      return json(existed ? 200 : 201, { ok: true, digest, alreadyExisted: existed });
    }
    const agent = /^\/v1\/agents\/(sha256:[0-9a-f]{64})$/.exec(path);
    if (method === 'GET' && agent) {
      const row = state.agents.get(agent[1]);
      if (!row) return json(404, { ok: false, error: bare ? 'not_found' : 'agent_not_registered' });
      if (bare) {
        return json(200, {
          digest: agent[1],
          descriptor: JSON.parse(row.canonicalBytes),
          name: row.name,
          organization: row.organization,
          registeredAt: row.at,
        });
      }
      return json(200, {
        ok: true,
        digest: agent[1],
        canonicalBytes: row.canonicalBytes,
        name: row.name,
        organization: row.organization,
        parent: row.parent,
        registeredAt: row.at,
      });
    }
    if (method === 'GET' && path === '/v1/agents' && agentList) {
      const name = url.searchParams.get('name');
      const limit = Number(url.searchParams.get('limit') ?? '100');
      const cursor = url.searchParams.get('cursor');
      if (bare) {
        // The platform's listing: ordered by digest, the cursor the last row's digest.
        if (cursor !== null && !/^sha256:[0-9a-f]{64}$/.test(cursor)) {
          return json(400, { ok: false, error: 'invalid_request', field: 'cursor' });
        }
        const all = [...state.agents.entries()]
          .map(([digest, r]) => ({ digest, ...r }))
          .sort((a, b) => (a.digest < b.digest ? -1 : 1))
          .filter((r) => (cursor === null || r.digest > cursor) && (name === null || r.name === name));
        const page = all.slice(0, limit);
        const nextCursor = all.length > limit && page.length > 0 ? page[page.length - 1].digest : null;
        return json(200, {
          agents: page.map((r) => ({
            digest: r.digest,
            descriptor: JSON.parse(r.canonicalBytes),
            name: r.name,
            organization: r.organization,
            registeredAt: r.at,
          })),
          nextCursor,
        });
      }
      if (cursor !== null && !/^[1-9][0-9]{0,15}$/.test(cursor)) {
        return json(400, { ok: false, error: 'invalid_request', reason: 'invalid_pagination' });
      }
      const after = Number(cursor ?? '0');
      const all = [...state.agents.entries()]
        .map(([digest, r], i) => ({ seq: i + 1, digest, ...r }))
        .filter((r) => r.seq > after && (name === null || r.name === name));
      const page = all.slice(0, limit);
      const next = all.length > limit && page.length > 0 ? String(page[page.length - 1].seq) : null;
      return json(200, {
        ok: true,
        rows: page.map((r) => ({
          digest: r.digest,
          canonicalBytes: r.canonicalBytes,
          name: r.name,
          organization: r.organization,
          parent: r.parent,
          registeredAt: r.at,
        })),
        cursor: next,
      });
    }
    return notFound();
  }) as unknown as typeof fetch;
  return state;
}

/**
 * The platform's capture check of a record's agent references: the first
 * that the catalog does not hold, or a `policy-engine` agent whose descriptor
 * names a model, as `{ reason, field }`; `null` when every reference holds.
 */
function agentRefusal(
  envelope: EvidenceEnvelope,
  agents: FakePlatform['agents'],
): { reason: 'agent_not_registered' | 'agent_kind_mismatch'; field: string } | null {
  const payload = envelope.payload as unknown as {
    decider?: { kind?: string; agent?: unknown } | null;
    contributions?: { steps?: Array<{ actor?: { kind?: string; agent?: unknown } | null }> } | null;
  };
  const refs: Array<{ field: string; kind: string | undefined; agent: string }> = [];
  if (typeof payload.decider?.agent === 'string') {
    refs.push({ field: 'payload.decider.agent', kind: payload.decider.kind, agent: payload.decider.agent });
  }
  (payload.contributions?.steps ?? []).forEach((step, i) => {
    if (typeof step.actor?.agent === 'string') {
      refs.push({ field: `payload.contributions.steps[${i}].actor.agent`, kind: step.actor.kind, agent: step.actor.agent });
    }
  });
  for (const ref of refs) {
    const row = agents.get(ref.agent);
    if (!row) return { reason: 'agent_not_registered', field: ref.field };
    const models = (JSON.parse(row.canonicalBytes) as { models: string[] }).models;
    if (ref.kind === 'policy-engine' && models.length > 0) return { reason: 'agent_kind_mismatch', field: ref.field };
  }
  return null;
}

/** A vendor-asserted model descriptor, every member present. */
export function modelDescriptor(modelName = 'claims-model', modelVersion = 'v1'): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor: 'example-vendor',
    modelName,
    modelVersion,
    modelType: 'llm',
    integrityTier: 'vendor-asserted',
    modelDigest: null,
    parentModelDescriptorDigest: null,
    derivation: null,
    trainedBy: null,
    license: null,
    modelCardUrl: null,
    training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
    regulatoryMarkings: [],
    externalIdentifiers: [],
  };
}

/** The digest every store computes for a model descriptor. */
export function modelDigest(descriptor: ModelDescriptor): string {
  return sha(canonicalSerializeDescriptor(descriptor));
}
