// tests/ts/wrappers/inline-descriptor-fallback.test.ts — a wrapped call on a store with no model catalog.
//
// A 0.8.0 record names a model only in a contribution step, by its catalogued
// descriptor digest. Over the cloud transport against a platform that does not
// serve the model catalog (`POST /v1/models` answers the catalog-less
// platform's catch-all 404), a wrapped call's model cannot be recorded: the
// wrapper builds no AI-BOM, logs `capture_model_not_recordable`, and captures
// the decision with `contributions: null`. A step `aiBom` the caller passes is
// refused as on any store that cannot resolve it. tests/ts/cloud-catalog.test.ts
// is the other half: the same calls against a platform that serves the catalog
// record the model.
import type { EvidenceEnvelope } from '@tzun/engine';
import { Tzun } from '../../../src/sdk/index';
import { fakePlatform } from '../helpers/fake-cloud-platform';

// Fake OpenAI-shaped client (duck-typed by attach()).
function fakeOpenAI() {
  return {
    chat: {
      completions: {
        create: async (_params: Record<string, unknown>) => ({
          id: 'r1', model: 'gpt-4o-2024-08-06',
          choices: [{ message: { content: 'approve' } }],
        }),
      },
    },
  };
}

/** A platform without the catalog endpoints, keeping the evidence POSTs in `posts`. */
function platformWithoutCatalog(posts: EvidenceEnvelope[]): typeof fetch {
  const platform = fakePlatform({ catalog: false });
  platform.evidence = posts;
  return platform.fetch;
}

const DECIDER = { kind: 'human' as const, id: 'acct:u-test' };

describe('a wrapped call over the HTTP transport, against a platform without the model catalog', () => {
  it('captures the decision without its model and logs capture_model_not_recordable', async () => {
    const posts: EvidenceEnvelope[] = [];
    const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
    const tzun = await Tzun.init({
      apiKey: 'tk_test',
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: platformWithoutCatalog(posts),
      onLog: (event: string, fields: Record<string, unknown>) => events.push({ event, fields }),
    } as Parameters<typeof Tzun.init>[0]);
    const captureSpy = jest.spyOn(tzun, 'capture');
    const client = tzun.attach(fakeOpenAI());
    const response = await client.chat.completions.create({
      model: 'gpt-4o', messages: [],
      tzun_capture: { decider: DECIDER, action: 'approved', reason: 'looks right' },
    } as never);

    expect(response).toMatchObject({ id: 'r1' });
    const result = await captureSpy.mock.results[0].value;
    expect(result.stored).toBe(true);
    expect(posts).toHaveLength(1);
    expect(posts[0].payload.contributions).toBeNull();
    expect(posts[0].payload.decider).toMatchObject(DECIDER);
    const lost = events.filter((e) => e.event === 'capture_model_not_recordable');
    expect(lost).toHaveLength(1);
    expect(lost[0].fields).toEqual({ vendor: 'openai', modelName: expect.any(String), reason: 'store_has_no_model_catalog' });
    expect(events.some((e) => e.event === 'connector_auto_registration')).toBe(false);
    expect(events.some((e) => e.event === 'capture_failure')).toBe(false);
    await tzun.close();
  });

  it('a caller-supplied inline step descriptor is refused before anything is sent, and the vendor response is returned', async () => {
    const posts: EvidenceEnvelope[] = [];
    const events: string[] = [];
    const tzun = await Tzun.init({
      apiKey: 'tk_test',
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: platformWithoutCatalog(posts),
      onLog: (event: string) => events.push(event),
    } as Parameters<typeof Tzun.init>[0]);
    const captureSpy = jest.spyOn(tzun, 'capture');
    const client = tzun.attach(fakeOpenAI());
    const inline = {
      modelDescriptor: {
        descriptorVersion: 'd1', vendor: 'openai', modelName: 'm', modelVersion: 'v1', modelType: 'llm',
        integrityTier: 'vendor-asserted', modelDigest: null, parentModelDescriptorDigest: null, derivation: null,
        trainedBy: 'x', license: 'mit', modelCardUrl: null,
        training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
        regulatoryMarkings: [], externalIdentifiers: [],
      },
      vendorFingerprint: null,
    };
    const response = await client.chat.completions.create({
      model: 'gpt-4o', messages: [],
      tzun_capture: { decider: DECIDER, action: 'approved', reason: 'looks right', aiBom: inline },
    } as never);

    expect(response).toMatchObject({ id: 'r1' });
    const result = await captureSpy.mock.results[0].value;
    expect(result.stored).toBe(false);
    expect(result.failure?.diagnosticMetadata).toMatchObject({ code: 'invalid_step_ai_bom', field: 'contributions.steps[0].aiBom' });
    expect(posts).toHaveLength(0);
    expect(events).toContain('capture_failure');
    await tzun.close();
  });

  it('hook() returns null and logs capture_model_not_recordable', async () => {
    const events: string[] = [];
    const tzun = await Tzun.init({
      apiKey: 'tk_test',
      _httpFetchFn: fakePlatform({ catalog: false }).fetch,
      onLog: (event: string) => events.push(event),
    } as Parameters<typeof Tzun.init>[0]);
    const bom = await tzun.hook('openai', { model: 'gpt-4o' }, { model: 'gpt-4o-2024-08-06' });
    expect(bom).toBeNull();
    expect(events).toEqual(['capture_model_not_recordable']);
    await tzun.close();
  });
});
