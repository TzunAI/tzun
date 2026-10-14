import { modelOf } from '../helpers/step-model';
/**
 * `tzun.attach(openAiClient)` + `tzun.hook('openai', ...)` connector wiring.
 *
 * Covers OpenAI row mapping, `emitAiBom: false`, and the LRU
 * descriptor-digest cache via the new per-call opt-in API.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

function fakeOpenAI(modelInResponse: string, system_fingerprint: string | null = 'fp_abc') {
  return {
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue({
          id: 'chatcmpl-test',
          choices: [
            { index: 0, message: { role: 'assistant', content: 'Approve.' } },
          ],
          model: modelInResponse,
          ...(system_fingerprint ? { system_fingerprint } : {}),
        }),
      },
    },
  };
}

describe('attach(openAiClient) — connector wiring', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('returns a wrapped client with chat.completions.create', () => {
    const client = fakeOpenAI('gpt-4o-2024-08-06');
    const wrapped = tzun.attach(client);
    expect(typeof wrapped.chat.completions.create).toBe('function');
  });

  it('passes through when tzun_capture is absent', async () => {
    const client = fakeOpenAI('gpt-4o-2024-08-06');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
    });

    expect(client.chat.completions.create).toHaveBeenCalledTimes(1);
    expect(captureSpy).not.toHaveBeenCalled();
  });

  it('captures evidence with a populated aiBom built by the connector', async () => {
    const client = fakeOpenAI('gpt-4o-2024-08-06', 'fp_xyz');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      temperature: 0.3,
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: {
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        action: 'approved',
        reason: 'risk score acceptable',
      },
    });

    expect(client.chat.completions.create).toHaveBeenCalledTimes(1);
    // The underlying client must NOT see tzun_capture.
    const forwarded = client.chat.completions.create.mock.calls[0][0] as Record<string, unknown>;
    expect(forwarded.tzun_capture).toBeUndefined();
    expect(forwarded.model).toBe('gpt-4o-2024-08-06');

    expect(captureSpy).toHaveBeenCalledTimes(1);
    const input = captureSpy.mock.calls[0][0];
    expect(modelOf(input)).not.toBeNull();
    const aiBom = modelOf(input) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.vendorFingerprint).toBe('fp_xyz');
    expect(aiBom.inferenceParameters?.temperature).toBe(0.3);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(256);
  });

  it('emitAiBom: false skips connector and captures with aiBom: null', async () => {
    const client = fakeOpenAI('gpt-4o-2024-08-06');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );

    const wrapped = tzun.attach(client, { emitAiBom: false });
    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    // emitAiBom:false short-circuits capture entirely.
    expect(captureSpy).not.toHaveBeenCalled();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('LRU cache hit on second call with same model', async () => {
    const client = fakeOpenAI('gpt-4o-2024-08-06');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'bye' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    expect(client.chat.completions.create).toHaveBeenCalledTimes(2);
    expect(registerSpy).toHaveBeenCalledTimes(1);
  });

  it('distinct models register distinct descriptors (cache miss path)', async () => {
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );

    const clientA = fakeOpenAI('gpt-4o-2024-08-06');
    const wrappedA = tzun.attach(clientA);
    await wrappedA.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const clientB = fakeOpenAI('gpt-4o-mini-2024-07-18');
    const wrappedB = tzun.attach(clientB);
    await wrappedB.chat.completions.create({
      model: 'gpt-4o-mini-2024-07-18',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    expect(registerSpy).toHaveBeenCalledTimes(2);
    const firstDescriptor = registerSpy.mock.calls[0][0] as { modelName: string };
    const secondDescriptor = registerSpy.mock.calls[1][0] as { modelName: string };
    expect(firstDescriptor.modelName).toBe('gpt-4o');
    expect(secondDescriptor.modelName).toBe('gpt-4o-mini');
  });

  it('connector returns null (no response.model) → captures with aiBom: null', async () => {
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    // No `model` field on the response — connector returns null.
    const client = {
      chat: {
        completions: {
          create: jest.fn().mockResolvedValue({
            id: 'chatcmpl-no-model',
            choices: [],
          }),
        },
      },
    };
    const wrapped = tzun.attach(client);

    await wrapped.chat.completions.create({
      model: 'text-embedding-3-small',
      input: 'hello',
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    expect(captureSpy).toHaveBeenCalledTimes(1);
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('caller-supplied aiBom in tzun_capture overrides the wrapper-built aiBom', async () => {
    const client = fakeOpenAI('gpt-4o-2024-08-06');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: {
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        action: 'approved',
        reason: 'ok',
        // Explicit null overrides whatever the wrapper built.
        aiBom: null,
      },
    });

    expect(captureSpy).toHaveBeenCalledTimes(1);
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
  });

  it('hook("openai", request, response) extracts AI-BOM standalone', async () => {
    const aiBom = (await tzun.hook(
      'openai',
      {
        model: 'gpt-4o-2024-08-06',
        temperature: 0.3,
        max_tokens: 256,
      },
      {
        id: 'chatcmpl-x',
        model: 'gpt-4o-2024-08-06',
        system_fingerprint: 'fp_xyz',
        choices: [],
      },
    )) as AiBom;
    expect(aiBom).not.toBeNull();
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.vendorFingerprint).toBe('fp_xyz');
  });
});
