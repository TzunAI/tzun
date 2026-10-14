import { modelOf } from '../helpers/step-model';
/**
 * `tzun.attach(bedrockClient)` + `tzun.hook('bedrock', ...)` connector wiring.
 *
 * Covers Bedrock row mapping, `emitAiBom: false`, and the LRU
 * descriptor-digest cache via the new per-call opt-in API.
 *
 * Bedrock's call surface is `client.send(command)`. The wrapper reads
 * `tzun_capture` off the command instance directly (since `send` is
 * single-argument) and forwards a copy with `tzun_capture` removed.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { AiBom } from '@tzun/engine';

class ConverseCommand {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
  constructor(public input: Record<string, unknown>) {}
}
class InvokeModelCommand {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
  constructor(public input: Record<string, unknown>) {}
}
class ListFoundationModelsCommand {
  // Control-plane command — wrapper should pass through (no model, connector
  // returns null skeleton, capture still fires but with aiBom:null).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
  constructor(public input: Record<string, unknown>) {}
}

class BedrockRuntimeClient {
  send = jest
    .fn()
    .mockImplementation(async (cmd: { input: Record<string, unknown> }) => ({
      output: { message: { role: 'assistant', content: [{ text: 'hi' }] } },
      stopReason: 'end_turn',
      _echoInput: cmd.input,
    }));
}

function attachTzunCapture<T extends object>(command: T, capture: { action: string; reason: string; decider: unknown }): T {
  (command as Record<string, unknown>).tzun_capture = capture;
  return command;
}

describe('attach(bedrockClient) — connector wiring', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('Converse: captures evidence with populated aiBom', async () => {
    const client = new BedrockRuntimeClient();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    const command = attachTzunCapture(
      new ConverseCommand({
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        messages: [{ role: 'user', content: [{ text: 'hi' }] }],
        inferenceConfig: {
          temperature: 0.2,
          topP: 0.9,
          maxTokens: 1024,
          stopSequences: ['END'],
        },
        region: 'us-east-1',
      }),
      { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    );
    await wrapped.send(command);

    expect(captureSpy).toHaveBeenCalledTimes(1);
    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.modelDescriptorDigest).toMatch(/^sha256:/);
    expect(aiBom.inferenceParameters?.temperature).toBe(0.2);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(1024);
    expect(aiBom.infrastructure?.provider).toBe('aws-bedrock');
    expect(aiBom.infrastructure?.region).toBe('us-east-1');

    // tzun_capture should NOT have reached the underlying client.
    const forwarded = client.send.mock.calls[0][0] as Record<string, unknown>;
    expect(forwarded.tzun_capture).toBeUndefined();
  });

  it('InvokeModel: captures evidence with populated aiBom', async () => {
    const client = new BedrockRuntimeClient();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    const command = attachTzunCapture(
      new InvokeModelCommand({
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        body: JSON.stringify({
          temperature: 0.4,
          top_p: 0.95,
          max_tokens: 512,
          stop_sequences: ['STOP'],
        }),
      }),
      { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    );
    await wrapped.send(command);

    const aiBom = modelOf(captureSpy.mock.calls[0][0]) as AiBom;
    expect(aiBom.inferenceParameters?.temperature).toBe(0.4);
    expect(aiBom.inferenceParameters?.maxTokens).toBe(512);
  });

  it('passes through when tzun_capture is absent', async () => {
    const client = new BedrockRuntimeClient();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.send(
      new ConverseCommand({
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        messages: [{ role: 'user', content: [{ text: 'hi' }] }],
        inferenceConfig: { temperature: 0.2 },
      }),
    );
    expect(client.send).toHaveBeenCalledTimes(1);
    expect(captureSpy).not.toHaveBeenCalled();
  });

  it('emitAiBom: false → no capture even with tzun_capture present', async () => {
    const client = new BedrockRuntimeClient();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );

    const wrapped = tzun.attach(client, { emitAiBom: false });
    const command = attachTzunCapture(
      new ConverseCommand({
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        messages: [{ role: 'user', content: [{ text: 'hi' }] }],
        inferenceConfig: { temperature: 0.2 },
      }),
      { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    );
    await wrapped.send(command);
    expect(captureSpy).not.toHaveBeenCalled();
    expect(registerSpy).not.toHaveBeenCalled();
  });

  it('LRU cache hit on second call', async () => {
    const client = new BedrockRuntimeClient();
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);
    await wrapped.send(
      attachTzunCapture(
        new ConverseCommand({
          modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
          messages: [{ role: 'user', content: [{ text: 'hi' }] }],
          inferenceConfig: { temperature: 0.2 },
        }),
        { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
      ),
    );
    await wrapped.send(
      attachTzunCapture(
        new ConverseCommand({
          modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
          messages: [{ role: 'user', content: [{ text: 'bye' }] }],
          inferenceConfig: { temperature: 0.5 },
        }),
        { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
      ),
    );
    expect(registerSpy).toHaveBeenCalledTimes(1);
  });

  it('distinct models register distinct descriptors (cache miss path)', async () => {
    const client = new BedrockRuntimeClient();
    const registerSpy = jest.spyOn(
      tzun.getStorage(),
      'registerModelDescriptor' as never,
    );
    const wrapped = tzun.attach(client);
    await wrapped.send(
      attachTzunCapture(
        new ConverseCommand({
          modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
          messages: [],
          inferenceConfig: {},
        }),
        { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
      ),
    );
    await wrapped.send(
      attachTzunCapture(
        new ConverseCommand({
          modelId: 'meta.llama3-70b-instruct-v1:0',
          messages: [],
          inferenceConfig: {},
        }),
        { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
      ),
    );
    expect(registerSpy).toHaveBeenCalledTimes(2);
  });

  it('connector returns null (no modelId) → captures with aiBom: null', async () => {
    const client = new BedrockRuntimeClient();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);
    await wrapped.send(
      attachTzunCapture(
        new ConverseCommand({
          // no modelId
          messages: [],
        }),
        { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
      ),
    );
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
  });

  it('non-inference commands without tzun_capture pass through cleanly', async () => {
    const client = new BedrockRuntimeClient();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);
    const result = await wrapped.send(new ListFoundationModelsCommand({}));
    expect(result).toBeDefined();
    expect(captureSpy).not.toHaveBeenCalled();
  });
});
