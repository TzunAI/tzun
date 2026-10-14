import { modelOf } from '../helpers/step-model';
/**
 * `tzun.attach(nimClient, { vendor: 'nvidia-nim' })` + `tzun.hook('nvidia-nim', ...)`.
 *
 * NIM uses an OpenAI-compatible surface, so detection requires an explicit
 * `{ vendor: 'nvidia-nim' }` override on AttachOptions. The wrapper sets
 * `vendor: 'nvidia-nim'` regardless of the underlying client type —
 * verified by the registered descriptor row's `vendor` field.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

function fakeNim(modelInResponse: string) {
  return {
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue({
          id: 'nim-test',
          choices: [
            { index: 0, message: { role: 'assistant', content: 'hi' } },
          ],
          model: modelInResponse,
        }),
      },
    },
  };
}

describe('attach(nimClient, { vendor: "nvidia-nim" }) — connector wiring', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('captures evidence with populated aiBom (vendor=nvidia-nim)', async () => {
    const client = fakeNim('meta/llama3-70b-instruct');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client, { vendor: 'nvidia-nim' });

    await wrapped.chat.completions.create({
      model: 'meta/llama3-70b-instruct',
      temperature: 0.3,
      top_p: 0.95,
      max_tokens: 256,
      seed: 7,
      stop: ['END'],
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.3);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(256);
    expect(aiBom.inferenceParameters?.seed).toBe(7);
    expect(aiBom.infrastructure?.provider).toBe('nvidia-nim');

    // The registered descriptor must reflect vendor=nvidia-nim regardless
    // of the OpenAI-compatible API surface.
    const registeredDescriptor = registerSpy.mock.calls[0][0] as { vendor: string };
    expect(registeredDescriptor.vendor).toBe('nvidia-nim');
  });

  it('passes through when tzun_capture is absent', async () => {
    const client = fakeNim('meta/llama3-70b-instruct');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client, { vendor: 'nvidia-nim' });

    await wrapped.chat.completions.create({
      model: 'meta/llama3-70b-instruct',
      messages: [{ role: 'user', content: 'hi' }],
    });

    expect(client.chat.completions.create).toHaveBeenCalledTimes(1);
    expect(captureSpy).not.toHaveBeenCalled();
  });

  it('emitAiBom: false → no capture even with tzun_capture present', async () => {
    const client = fakeNim('meta/llama3-70b-instruct');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client, { vendor: 'nvidia-nim', emitAiBom: false });
    await wrapped.chat.completions.create({
      model: 'meta/llama3-70b-instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(captureSpy).not.toHaveBeenCalled();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('LRU cache hit on second call', async () => {
    const client = fakeNim('meta/llama3-70b-instruct');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client, { vendor: 'nvidia-nim' });
    await wrapped.chat.completions.create({
      model: 'meta/llama3-70b-instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    await wrapped.chat.completions.create({
      model: 'meta/llama3-70b-instruct',
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

    const clientA = fakeNim('meta/llama3-70b-instruct');
    const wrappedA = tzun.attach(clientA, { vendor: 'nvidia-nim' });
    await wrappedA.chat.completions.create({
      model: 'meta/llama3-70b-instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const clientB = fakeNim('mistral/mixtral-8x7b-instruct');
    const wrappedB = tzun.attach(clientB, { vendor: 'nvidia-nim' });
    await wrappedB.chat.completions.create({
      model: 'mistral/mixtral-8x7b-instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(registerSpy).toHaveBeenCalledTimes(2);
  });

  it('connector returns null (no response.model) → captures with aiBom: null', async () => {
    const captureSpy = jest.spyOn(tzun, 'capture');
    const client = {
      chat: {
        completions: {
          create: jest.fn().mockResolvedValue({
            id: 'nim-empty',
            choices: [],
          }),
        },
      },
    };
    const wrapped = tzun.attach(client, { vendor: 'nvidia-nim' });
    await wrapped.chat.completions.create({
      model: 'whatever',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
  });
});
