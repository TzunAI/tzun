import { modelOf } from '../helpers/step-model';
/**
 * `tzun.attach(hfClient)` + `tzun.hook('hf-inference', ...)` connector wiring.
 *
 * Covers HF Inference row mapping, `emitAiBom: false`, and the LRU
 * descriptor-digest cache via the new per-call opt-in API.
 *
 * The wrapper intercepts `chatCompletion` and `textGeneration`. The HF
 * connector resolves `params.model` (form `<org>/<model>`) or extracts the
 * model id from a `/models/...` endpoint URL.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

function fakeHf() {
  return {
    chatCompletion: jest.fn().mockResolvedValue({
      choices: [{ message: { role: 'assistant', content: 'hi' } }],
    }),
    textGeneration: jest.fn().mockResolvedValue({
      generated_text: 'hi',
    }),
  };
}

describe('attach(hfClient) — connector wiring', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('chatCompletion: captures evidence with populated aiBom', async () => {
    const client = fakeHf();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.chatCompletion({
      model: 'meta-llama/Llama-3.1-8B-Instruct',
      parameters: {
        temperature: 0.3,
        top_p: 0.95,
        max_new_tokens: 256,
        stop: ['END'],
      },
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.3);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(256);
    expect(aiBom.infrastructure?.provider).toBe('hf-inference');
  });

  it('textGeneration: captures evidence with populated aiBom (endpoint-derived model id)', async () => {
    const client = fakeHf();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.textGeneration({
      endpoint:
        'https://api-inference.huggingface.co/models/meta-llama/Llama-3.1-8B-Instruct',
      parameters: {
        temperature: 0.5,
        max_new_tokens: 128,
      },
      inputs: 'hi',
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.5);
    expect(aiBom.infrastructure?.endpoint).toBe(
      'https://api-inference.huggingface.co/models/meta-llama/Llama-3.1-8B-Instruct',
    );
  });

  it('passes through when tzun_capture is absent', async () => {
    const client = fakeHf();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.chatCompletion({
      model: 'meta-llama/Llama-3.1-8B-Instruct',
      messages: [{ role: 'user', content: 'hi' }],
    });

    expect(client.chatCompletion).toHaveBeenCalledTimes(1);
    expect(captureSpy).not.toHaveBeenCalled();
  });

  it('emitAiBom: false → no capture even with tzun_capture present', async () => {
    const client = fakeHf();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client, { emitAiBom: false });
    await wrapped.chatCompletion({
      model: 'meta-llama/Llama-3.1-8B-Instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(captureSpy).not.toHaveBeenCalled();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('LRU cache hit on second call', async () => {
    const client = fakeHf();
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);
    await wrapped.chatCompletion({
      model: 'meta-llama/Llama-3.1-8B-Instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    await wrapped.chatCompletion({
      model: 'meta-llama/Llama-3.1-8B-Instruct',
      messages: [{ role: 'user', content: 'bye' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(registerSpy).toHaveBeenCalledTimes(1);
  });

  it('distinct models register distinct descriptors (cache miss path)', async () => {
    const client = fakeHf();
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);
    await wrapped.chatCompletion({
      model: 'meta-llama/Llama-3.1-8B-Instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    await wrapped.chatCompletion({
      model: 'mistralai/Mixtral-8x7B-Instruct-v0.1',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(registerSpy).toHaveBeenCalledTimes(2);
  });

  it('connector returns null (no model, no endpoint) → captures with aiBom: null', async () => {
    const captureSpy = jest.spyOn(tzun, 'capture');
    const client = {
      chatCompletion: jest.fn().mockResolvedValue({
        choices: [{ message: { role: 'assistant', content: 'hi' } }],
      }),
    };
    const wrapped = tzun.attach(client);
    await wrapped.chatCompletion({
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
  });
});
