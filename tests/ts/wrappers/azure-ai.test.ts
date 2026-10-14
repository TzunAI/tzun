import { modelOf } from '../helpers/step-model';
/**
 * `tzun.attach(azureAiClient)` + `tzun.hook('azure-ai', ...)` connector wiring.
 *
 * Covers Azure AI Foundry row mapping (Phi, Mistral, Cohere, etc.),
 * `emitAiBom: false`, and the LRU descriptor-digest cache via the new
 * per-call opt-in API. The Azure-OpenAI surface uses `attach()` against an
 * OpenAI-compatible client pointed at the Azure deployment URL.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

function fakeAzureAi(modelInResponse: string) {
  return {
    complete: jest.fn().mockResolvedValue({
      id: 'cmpl-azure',
      choices: [{ message: { role: 'assistant', content: 'hi' } }],
      model: modelInResponse,
    }),
    getChatCompletions: jest.fn().mockResolvedValue({
      id: 'chat-azure',
      choices: [{ message: { role: 'assistant', content: 'hi' } }],
      model: modelInResponse,
    }),
  };
}

describe('attach(azureAiClient) — connector wiring', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('complete: captures evidence with populated aiBom', async () => {
    const client = fakeAzureAi('Phi-3.5-MoE-instruct');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.complete({
      model: 'Phi-3.5-MoE-instruct',
      temperature: 0.3,
      max_tokens: 256,
      stop: ['END'],
      azure_endpoint: 'https://my-foundry.eastus.inference.ai.azure.com',
      api_version: '2024-08-01',
      azure_region: 'eastus',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.3);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(256);
    expect(aiBom.infrastructure?.provider).toBe('azure-ai');
    expect(aiBom.infrastructure?.region).toBe('eastus');
  });

  it('getChatCompletions: captures evidence with populated aiBom', async () => {
    const client = fakeAzureAi('Mistral-large-2407');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.getChatCompletions({
      model: 'Mistral-large-2407',
      temperature: 0.5,
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.5);
  });

  it('passes through when tzun_capture is absent', async () => {
    const client = fakeAzureAi('Phi-3.5-MoE-instruct');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.complete({
      model: 'Phi-3.5-MoE-instruct',
      messages: [{ role: 'user', content: 'hi' }],
    });

    expect(client.complete).toHaveBeenCalledTimes(1);
    expect(captureSpy).not.toHaveBeenCalled();
  });

  it('emitAiBom: false → no capture even when tzun_capture present', async () => {
    const client = fakeAzureAi('Phi-3.5-MoE-instruct');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client, { emitAiBom: false });
    await wrapped.complete({
      model: 'Phi-3.5-MoE-instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(captureSpy).not.toHaveBeenCalled();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('LRU cache hit on second call', async () => {
    const client = fakeAzureAi('Phi-3.5-MoE-instruct');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);
    await wrapped.complete({
      model: 'Phi-3.5-MoE-instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    await wrapped.complete({
      model: 'Phi-3.5-MoE-instruct',
      messages: [{ role: 'user', content: 'bye' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(registerSpy).toHaveBeenCalledTimes(1);
  });

  it('distinct models register distinct descriptors (cache miss path)', async () => {
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const clientA = fakeAzureAi('Phi-3.5-MoE-instruct');
    const wrappedA = tzun.attach(clientA);
    await wrappedA.complete({
      model: 'Phi-3.5-MoE-instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const clientB = fakeAzureAi('Mistral-large-2407');
    const wrappedB = tzun.attach(clientB);
    await wrappedB.complete({
      model: 'Mistral-large-2407',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(registerSpy).toHaveBeenCalledTimes(2);
  });

  it('connector returns null (no response.model) → captures with aiBom: null', async () => {
    const captureSpy = jest.spyOn(tzun, 'capture');
    const client = {
      complete: jest.fn().mockResolvedValue({
        id: 'cmpl-empty',
        choices: [],
      }),
    };
    const wrapped = tzun.attach(client);
    await wrapped.complete({
      model: 'whatever',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
  });
});
