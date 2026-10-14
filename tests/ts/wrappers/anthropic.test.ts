import { modelOf } from '../helpers/step-model';
/**
 * `tzun.attach(anthropicClient)` + `tzun.hook('anthropic', ...)` connector wiring.
 *
 * Covers Anthropic row mapping, `emitAiBom: false`, and the LRU
 * descriptor-digest cache via the new per-call opt-in API.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

function fakeAnthropic(modelInResponse: string) {
  return {
    messages: {
      create: jest.fn().mockResolvedValue({
        id: 'msg-test',
        content: [{ type: 'text', text: 'Approve.' }],
        model: modelInResponse,
      }),
    },
  };
}

describe('attach(anthropicClient) — connector wiring', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('returns a wrapped client with messages.create', () => {
    const client = fakeAnthropic('claude-3-5-sonnet-20241022');
    const wrapped = tzun.attach(client);
    expect(typeof wrapped.messages.create).toBe('function');
  });

  it('passes through when tzun_capture is absent', async () => {
    const client = fakeAnthropic('claude-3-5-sonnet-20241022');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hi' }],
    });

    expect(client.messages.create).toHaveBeenCalledTimes(1);
    expect(captureSpy).not.toHaveBeenCalled();
  });

  it('captures evidence with a populated aiBom built by the connector', async () => {
    const client = fakeAnthropic('claude-3-5-sonnet-20241022');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 512,
      temperature: 0.2,
      stop_sequences: ['END'],
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'meets compliance' },
    });

    expect(captureSpy).toHaveBeenCalledTimes(1);
    const input = captureSpy.mock.calls[0][0];
    const aiBom = modelOf(input) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.2);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(512);
    expect(aiBom.inferenceParameters?.stopSequences).toEqual(['END']);
    expect(aiBom.vendorFingerprint).toBeNull();
    expect(aiBom.inferenceParameters?.seed).toBeNull();

    // tzun_capture should have been stripped from the forwarded params.
    const forwarded = client.messages.create.mock.calls[0][0] as Record<string, unknown>;
    expect(forwarded.tzun_capture).toBeUndefined();
  });

  it('emitAiBom: false skips capture entirely', async () => {
    const client = fakeAnthropic('claude-3-5-sonnet-20241022');
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );

    const wrapped = tzun.attach(client, { emitAiBom: false });
    await wrapped.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    expect(captureSpy).not.toHaveBeenCalled();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('LRU cache hit on second call', async () => {
    const client = fakeAnthropic('claude-3-5-sonnet-20241022');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);

    await wrapped.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    await wrapped.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 256,
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

    const clientA = fakeAnthropic('claude-3-5-sonnet-20241022');
    const wrappedA = tzun.attach(clientA);
    await wrappedA.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    const clientB = fakeAnthropic('claude-3-5-haiku-20241022');
    const wrappedB = tzun.attach(clientB);
    await wrappedB.messages.create({
      model: 'claude-3-5-haiku-20241022',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    expect(registerSpy).toHaveBeenCalledTimes(2);
  });

  it('connector returns null (no response.model) → captures with aiBom: null', async () => {
    const captureSpy = jest.spyOn(tzun, 'capture');
    const client = {
      messages: {
        create: jest.fn().mockResolvedValue({
          id: 'msg-empty',
          content: [],
        }),
      },
    };
    const wrapped = tzun.attach(client);
    await wrapped.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
  });

  it('hook("anthropic", request, response) extracts AI-BOM standalone', async () => {
    const aiBom = (await tzun.hook(
      'anthropic',
      {
        model: 'claude-3-5-sonnet-20241022',
        max_tokens: 512,
        temperature: 0.2,
      },
      {
        id: 'msg-x',
        content: [{ type: 'text', text: 'ok' }],
        model: 'claude-3-5-sonnet-20241022',
      },
    )) as AiBom;
    expect(aiBom).not.toBeNull();
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.2);
  });
});
