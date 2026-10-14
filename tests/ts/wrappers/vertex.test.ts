import { modelOf } from '../helpers/step-model';
/**
 * `tzun.attach(vertexClient)` + `tzun.hook('vertex', ...)` connector wiring.
 *
 * Covers Vertex row mapping, `emitAiBom: false`, and the LRU
 * descriptor-digest cache via the per-call opt-in API. The wrapper
 * intercepts `generateContent` (Gemini-family) and `predict` (PaLM +
 * publisher models). Both are duck-typed.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

function fakeVertex() {
  return {
    generateContent: jest.fn().mockResolvedValue({
      candidates: [{ content: { parts: [{ text: 'hi' }] } }],
      usageMetadata: { totalTokenCount: 12 },
    }),
    predict: jest.fn().mockResolvedValue({
      predictions: [{ content: 'hi' }],
    }),
  };
}

describe('attach(vertexClient) — connector wiring', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('generateContent: captures evidence with populated aiBom', async () => {
    const client = fakeVertex();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.generateContent({
      model: 'gemini-1.5-pro-001',
      contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
      generationConfig: {
        temperature: 0.3,
        topP: 0.9,
        maxOutputTokens: 256,
        stopSequences: ['END'],
      },
      location: 'us-central1',
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.3);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(256);
    expect(aiBom.infrastructure?.provider).toBe('gcp-vertex');
    expect(aiBom.infrastructure?.region).toBe('us-central1');
  });

  it('predict: captures evidence with populated aiBom', async () => {
    const client = fakeVertex();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.predict({
      endpoint:
        'projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro-001',
      instances: [{ content: 'hi' }],
      parameters: {
        temperature: 0.5,
        topP: 0.8,
        maxOutputTokens: 128,
      },
      location: 'us-central1',
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.5);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(128);
  });

  it('passes through when tzun_capture is absent', async () => {
    const client = fakeVertex();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.generateContent({
      model: 'gemini-1.5-pro-001',
      contents: [],
      generationConfig: {},
    });

    expect(client.generateContent).toHaveBeenCalledTimes(1);
    expect(captureSpy).not.toHaveBeenCalled();
  });

  it('emitAiBom: false → no capture even with tzun_capture present', async () => {
    const client = fakeVertex();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client, { emitAiBom: false });
    await wrapped.generateContent({
      model: 'gemini-1.5-pro-001',
      contents: [],
      generationConfig: { temperature: 0.2 },
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(captureSpy).not.toHaveBeenCalled();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('LRU cache hit on second call', async () => {
    const client = fakeVertex();
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);
    await wrapped.generateContent({
      model: 'gemini-1.5-pro-001',
      contents: [],
      generationConfig: { temperature: 0.2 },
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    await wrapped.generateContent({
      model: 'gemini-1.5-pro-001',
      contents: [],
      generationConfig: { temperature: 0.7 },
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(registerSpy).toHaveBeenCalledTimes(1);
  });

  it('distinct models register distinct descriptors (cache miss path)', async () => {
    const client = fakeVertex();
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);
    await wrapped.generateContent({
      model: 'gemini-1.5-pro-001',
      contents: [],
      generationConfig: {},
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    await wrapped.generateContent({
      model: 'gemini-1.5-flash-001',
      contents: [],
      generationConfig: {},
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(registerSpy).toHaveBeenCalledTimes(2);
  });

  it('connector returns null (no model + no endpoint) → captures with aiBom: null', async () => {
    const client = fakeVertex();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);
    await wrapped.generateContent({
      // no model, no endpoint, just a generationConfig — connector returns null.
      contents: [],
      generationConfig: {},
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
  });
});

/**
 * The documented integration recipe produces a full AI-BOM.
 *
 * `@google-cloud/vertexai` puts the model id on the `GenerativeModel`
 * instance and the region on the `VertexAI` client; the request object the
 * AI-BOM integration guide tells integrators to write carries only
 * `{ contents, generationConfig, tzun_capture }`. The wrapper reads the model
 * and location off the instance when the request omits them. Forwarding only
 * `args[0]` would leave the connector with no `model`, so it would return
 * `null` and the capture would be stored with no model identity, no
 * inference parameters and no region. When no model can be found anywhere,
 * `connector_no_aibom` on the log sink says so.
 */
describe('attach(vertexClient) — model/location live on the instance', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  /** A GenerativeModel as the real SDK builds it: id + region on the object. */
  function fakeGenerativeModel() {
    return {
      model: 'gemini-1.5-pro-002',
      location: 'europe-west4',
      generateContent: jest.fn().mockResolvedValue({
        response: {
          modelVersion: 'gemini-1.5-pro-002',
          candidates: [{ content: { parts: [{ text: 'hi' }] } }],
        },
      }),
    };
  }

  it('builds a full AI-BOM from the instance when the request omits model/location', async () => {
    const client = fakeGenerativeModel();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    // Exactly the shape docs/integration/ai-bom-runbook.md tells users to write.
    await wrapped.generateContent({
      contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
      generationConfig: { temperature: 0.2, topP: 0.8, maxOutputTokens: 512 },
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom).not.toBeNull();
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.2);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(512);
    expect(aiBom.infrastructure?.region).toBe('europe-west4');
  });

  it('accepts @google/genai `config` as an alias of `generationConfig`', async () => {
    const client = fakeGenerativeModel();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.generateContent({
      contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
      config: { temperature: 0.7, maxOutputTokens: 64 },
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.inferenceParameters?.temperature).toBe(0.7);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(64);
  });

  it('an explicit request-level model still wins over the instance', async () => {
    const client = fakeGenerativeModel();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.generateContent({
      model: 'gemini-1.5-flash-001',
      location: 'us-central1',
      contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
      generationConfig: { temperature: 0.1 },
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.infrastructure?.region).toBe('us-central1');
    expect(
      (aiBom as unknown as { modelDescriptor?: { modelId?: string } })
        .modelDescriptor?.modelId ?? 'gemini-1.5-flash-001',
    ).toBe('gemini-1.5-flash-001');
  });

  it('emits connector_no_aibom when the connector still cannot name a model', async () => {
    const events: string[] = [];
    const logged = await Tzun.init({ onLog: (e: string) => events.push(e) });
    try {
      // No model anywhere: not on the request, not on the instance.
      const client = {
        generateContent: jest.fn().mockResolvedValue({ response: {} }),
      };
      const wrapped = logged.attach(client, { vendor: 'vertex' });
      await wrapped.generateContent({
        contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
        generationConfig: { temperature: 0.2 },
        tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
      });
      expect(events).toContain('connector_no_aibom');
    } finally {
      await logged.close();
    }
  });
});
