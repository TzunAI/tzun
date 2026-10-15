import { modelOf } from '../helpers/step-model';
/**
 * OpenRouter through `attach()`, `wrapOpenRouter` and `hook('openrouter')`.
 *
 * An OpenAI SDK client pointed at OpenRouter has OpenAI's call surface, so
 * `attach()` tells them apart by the client's base URL: a host of
 * `openrouter.ai` is the gateway. Its captures register a descriptor with
 * `vendor: 'openrouter'` (not `openai`), record the base URL as
 * `infrastructure.endpoint` and the upstream OpenRouter names as
 * `infrastructure.provider`. The base URL is read off the client instance
 * and given to the connector only; it never reaches the forwarded call.
 *
 * The fake clients and responses are synthetic.
 */

import { Tzun } from '../../../src/sdk/index';
import {
  __resetKnownModelsCacheForTests,
  detectVendor,
  extractOpenRouterClientHints,
  wrapOpenRouter,
  wrapOpenAI,
} from '../../../src/sdk/wrappers';
import type { AiBom, ModelDescriptor } from '@tzun/engine';

const DECIDER = { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null };

/** `provider: null` leaves the member out, as a response that names no upstream. */
function gatewayResponse(model: string, provider: string | null = 'Nvidia'): Record<string, unknown> {
  return {
    id: 'gen-0000000000-scrubbed000000000000',
    object: 'chat.completion',
    created: 1790000000,
    model,
    ...(provider === null ? {} : { provider }),
    system_fingerprint: null,
    service_tier: null,
    choices: [
      {
        index: 0,
        finish_reason: 'stop',
        native_finish_reason: 'stop',
        logprobs: null,
        message: { role: 'assistant', content: 'approve', refusal: null, reasoning: null },
      },
    ],
    usage: { prompt_tokens: 10, completion_tokens: 1, total_tokens: 11 },
  };
}

/** An OpenAI-SDK-shaped client: the base URL on the instance, as openai-node keeps it. */
function fakeClient(baseURL: string | undefined, response: Record<string, unknown>) {
  return {
    ...(baseURL === undefined ? {} : { baseURL }),
    apiKey: 'placeholder',
    chat: { completions: { create: jest.fn().mockResolvedValue(response) } },
  };
}

describe('OpenRouter through attach()', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('detects a client on openrouter.ai and records the gateway truthfully', async () => {
    const client = fakeClient('https://openrouter.ai/api/v1', gatewayResponse('nvidia/nemotron-3-super-120b-a12b:free'));
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(tzun.getStorage(), 'registerModelDescriptor' as never);

    const wrapped = tzun.attach(client);
    await wrapped.chat.completions.create({
      model: 'nvidia/nemotron-3-super-120b-a12b:free',
      messages: [{ role: 'user', content: 'Approve?' }],
      temperature: 0.2,
      max_tokens: 1200,
      tzun_capture: { decider: DECIDER, action: 'approved', reason: 'ok' },
    });

    // The forwarded call carries neither the capture kwarg nor the endpoint hint.
    const forwarded = client.chat.completions.create.mock.calls[0][0];
    expect(forwarded.tzun_capture).toBeUndefined();
    expect('openrouter_endpoint' in forwarded).toBe(false);
    expect(Object.keys(forwarded).sort()).toEqual(['max_tokens', 'messages', 'model', 'temperature']);

    const descriptor = registerSpy.mock.calls[0][0] as ModelDescriptor;
    expect(descriptor.vendor).toBe('openrouter');
    expect(descriptor.modelName).toBe('nvidia/nemotron-3-super-120b-a12b:free');
    expect(descriptor.trainedBy).toBe('nvidia');
    expect(descriptor.license).toBe('nvidia-nemotron-open-model-license');
    expect(descriptor.integrityTier).toBe('vendor-asserted');

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(aiBom.infrastructure).toEqual({
      provider: 'Nvidia',
      region: null,
      apiVersion: null,
      endpoint: 'https://openrouter.ai/api/v1',
    });
    expect(aiBom.inferenceParameters).toEqual({
      temperature: 0.2,
      topP: null,
      maxTokens: 1200,
      seed: null,
      stopSequences: null,
    });

    // The record is stored, and its aiOutput keeps the gateway's own facts.
    const records = await tzun.list({});
    expect(records).toHaveLength(1);
    const aiOutput = records[0].envelope.payload.aiOutput as Record<string, unknown>;
    expect(aiOutput.provider).toBe('Nvidia');
    expect(aiOutput.model).toBe('nvidia/nemotron-3-super-120b-a12b:free');
    const stored = modelOf(records[0].envelope.payload) as AiBom;
    expect(stored.infrastructure?.endpoint).toBe('https://openrouter.ai/api/v1');
  });

  it('openai-python style trailing slash records the same endpoint', async () => {
    const client = fakeClient('https://openrouter.ai/api/v1/', gatewayResponse('openai/gpt-6-astra', 'OpenAI'));
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);
    await wrapped.chat.completions.create({
      model: 'openai/gpt-6-astra',
      messages: [],
      tzun_capture: { decider: DECIDER, action: 'a', reason: 'b' },
    });
    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.infrastructure?.endpoint).toBe('https://openrouter.ai/api/v1');
    expect(aiBom.infrastructure?.provider).toBe('OpenAI');
  });

  it('an unnormalised base URL records the endpoint openai-python would', async () => {
    // openai-node keeps `baseURL` as given; openai-python keeps an httpx.URL,
    // which lowercases the host and drops the default port. The connector
    // applies the same normalisation, so both SDKs record one endpoint.
    const client = fakeClient('https://OpenRouter.AI:443/api/v1', gatewayResponse('openai/gpt-6-astra', 'OpenAI'));
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);
    await wrapped.chat.completions.create({
      model: 'openai/gpt-6-astra',
      messages: [],
      tzun_capture: { decider: DECIDER, action: 'a', reason: 'b' },
    });
    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.infrastructure?.endpoint).toBe('https://openrouter.ai/api/v1');
  });

  it('{ vendor: "openai" } restores the openai classification', async () => {
    const client = fakeClient('https://openrouter.ai/api/v1', gatewayResponse('openai/gpt-6-astra', 'OpenAI'));
    const registerSpy = jest.spyOn(tzun.getStorage(), 'registerModelDescriptor' as never);
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client, { vendor: 'openai' });
    await wrapped.chat.completions.create({
      model: 'openai/gpt-6-astra',
      messages: [],
      tzun_capture: { decider: DECIDER, action: 'a', reason: 'b' },
    });
    expect((registerSpy.mock.calls[0][0] as ModelDescriptor).vendor).toBe('openai');
    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    // The openai connector claims no infrastructure for a non-Azure client.
    expect(aiBom.infrastructure).toBeNull();
  });

  it('a client on another host stays openai and records no OpenRouter facts', async () => {
    const client = fakeClient('https://api.openai.com/v1', {
      id: 'chatcmpl-test',
      model: 'gpt-4o-2024-08-06',
      choices: [{ index: 0, message: { role: 'assistant', content: 'ok' } }],
    });
    const registerSpy = jest.spyOn(tzun.getStorage(), 'registerModelDescriptor' as never);
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);
    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [],
      tzun_capture: { decider: DECIDER, action: 'a', reason: 'b' },
    });
    expect((registerSpy.mock.calls[0][0] as ModelDescriptor).vendor).toBe('openai');
    expect((modelOf(captureSpy.mock.calls[0][0]) as AiBom).infrastructure).toBeNull();
  });

  it('wrapOpenRouter pins the vendor for a gateway behind another host', async () => {
    const client = fakeClient('https://gateway.example.com/openrouter/v1', gatewayResponse('x-ai/grok-4.7', 'xAI'));
    const registerSpy = jest.spyOn(tzun.getStorage(), 'registerModelDescriptor' as never);
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = wrapOpenRouter(client, tzun);
    await wrapped.chat.completions.create({
      model: 'x-ai/grok-4.7',
      messages: [],
      tzun_capture: { decider: DECIDER, action: 'a', reason: 'b' },
    });
    const descriptor = registerSpy.mock.calls[0][0] as ModelDescriptor;
    expect(descriptor.vendor).toBe('openrouter');
    expect(descriptor.trainedBy).toBe('x-ai');
    expect(descriptor.license).toBe('xai-commercial');
    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.infrastructure).toEqual({
      provider: 'xAI',
      region: null,
      apiVersion: null,
      endpoint: 'https://gateway.example.com/openrouter/v1',
    });
    expect('openrouter_endpoint' in client.chat.completions.create.mock.calls[0][0]).toBe(false);
  });

  it('wrapOpenRouter on a client with no baseURL records no endpoint', async () => {
    const client = fakeClient(undefined, gatewayResponse('qwen/qwen3.8-27b', null));
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = wrapOpenRouter(client, tzun);
    await wrapped.chat.completions.create({
      model: 'qwen/qwen3.8-27b',
      messages: [],
      tzun_capture: { decider: DECIDER, action: 'a', reason: 'b' },
    });
    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.infrastructure).toEqual({ provider: null, region: null, apiVersion: null, endpoint: null });
  });

  it('wrapOpenAI on an OpenRouter client keeps the explicit openai pin', () => {
    const client = fakeClient('https://openrouter.ai/api/v1', gatewayResponse('openai/gpt-6-astra'));
    // The alias passes `vendor: 'openai'`, which wins over detection.
    expect(() => wrapOpenAI(client, tzun)).not.toThrow();
    expect(detectVendor(client, { vendor: 'openai' })).toBe('openai');
  });

  it('a capture of the served model, not the requested one, with an explicit kwarg winning', async () => {
    const client = fakeClient('https://openrouter.ai/api/v1', gatewayResponse('anthropic/claude-haiku-5.5', 'Anthropic'));
    const registerSpy = jest.spyOn(tzun.getStorage(), 'registerModelDescriptor' as never);
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);
    await wrapped.chat.completions.create({
      model: 'openrouter/auto',
      messages: [],
      tzun_capture: { decider: DECIDER, action: 'a', reason: 'b' },
    });
    expect((registerSpy.mock.calls[0][0] as ModelDescriptor).modelName).toBe('anthropic/claude-haiku-5.5');
    expect((modelOf(captureSpy.mock.calls[0][0]) as AiBom).infrastructure?.provider).toBe('Anthropic');
  });

  it('passes through without capture when tzun_capture is absent', async () => {
    const client = fakeClient('https://openrouter.ai/api/v1', gatewayResponse('openai/gpt-6-astra'));
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);
    await wrapped.chat.completions.create({ model: 'openai/gpt-6-astra', messages: [] });
    expect(captureSpy).not.toHaveBeenCalled();
    expect(Object.keys(client.chat.completions.create.mock.calls[0][0]).sort()).toEqual(['messages', 'model']);
  });
});

describe('detectVendor and the OpenRouter base URL', () => {
  const shape = (baseURL: unknown) => ({ baseURL, chat: { completions: { create: () => undefined } } });

  it.each<[unknown, string]>([
    ['https://openrouter.ai/api/v1', 'openrouter'],
    ['https://OpenRouter.ai:443/api/v1/', 'openrouter'],
    ['https://api.openai.com/v1', 'openai'],
    ['https://openrouter.ai.example.com/api/v1', 'openai'],
    ['https://openrouter.ai@gateway.example.com/v1', 'openai'],
    ['https://contoso.openai.azure.com', 'openai'],
    [undefined, 'openai'],
    [42, 'openai'],
  ])('baseURL %j → %s', (baseURL, vendor) => {
    expect(detectVendor(shape(baseURL))).toBe(vendor);
  });

  it('an explicit vendor wins over the base URL', () => {
    expect(detectVendor(shape('https://openrouter.ai/api/v1'), { vendor: 'nvidia-nim' })).toBe('nvidia-nim');
    expect(detectVendor(shape('https://api.openai.com/v1'), { vendor: 'openrouter' })).toBe('openrouter');
  });

  it('a baseURL without the chat-completions surface is not OpenRouter', () => {
    expect(() => detectVendor({ baseURL: 'https://openrouter.ai/api/v1' })).toThrow(/openrouter/);
  });
});

describe('extractOpenRouterClientHints', () => {
  it('reads a string baseURL off the instance, verbatim', () => {
    expect(extractOpenRouterClientHints({ baseURL: 'https://openrouter.ai/api/v1/' })).toEqual({
      openrouter_endpoint: 'https://openrouter.ai/api/v1/',
    });
  });

  it('returns {} when there is no string baseURL', () => {
    expect(extractOpenRouterClientHints({})).toEqual({});
    expect(extractOpenRouterClientHints({ baseURL: 7 })).toEqual({});
  });
});

describe("tzun.hook('openrouter', ...)", () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('builds an AI-BOM with the endpoint the caller passes', async () => {
    const aiBom = (await tzun.hook(
      'openrouter',
      { model: 'mistralai/mistral-small-2603', seed: 7, openrouter_endpoint: 'https://openrouter.ai/api/v1' },
      gatewayResponse('mistralai/mistral-small-2603', 'Mistral'),
    )) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.seed).toBe(7);
    expect(aiBom.infrastructure).toEqual({
      provider: 'Mistral',
      region: null,
      apiVersion: null,
      endpoint: 'https://openrouter.ai/api/v1',
    });
  });

  it('assumes no endpoint when the caller passes none', async () => {
    const aiBom = (await tzun.hook(
      'openrouter',
      { model: 'mistralai/mistral-small-2603' },
      gatewayResponse('mistralai/mistral-small-2603', 'Mistral'),
    )) as AiBom;
    expect(aiBom.infrastructure?.endpoint).toBeNull();
  });

  it('returns null for a response with no model', async () => {
    const response = gatewayResponse('x');
    delete response.model;
    expect(await tzun.hook('openrouter', { model: 'openai/gpt-6-astra' }, response)).toBeNull();
  });

  it('a :free id and its base register distinct descriptors', async () => {
    const registerSpy = jest.spyOn(tzun.getStorage(), 'registerModelDescriptor' as never);
    const a = (await tzun.hook('openrouter', {}, gatewayResponse('google/gemma-4-31b-it'))) as AiBom;
    const b = (await tzun.hook('openrouter', {}, gatewayResponse('google/gemma-4-31b-it:free'))) as AiBom;
    expect(registerSpy).toHaveBeenCalledTimes(2);
    expect(a.modelDescriptorDigest).not.toBe(b.modelDescriptorDigest);
  });
});
