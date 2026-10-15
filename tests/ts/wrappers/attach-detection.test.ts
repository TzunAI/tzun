/**
 * `Tzun#attach()` duck-type detection matrix.
 *
 * One block per vendor shape. Each block:
 *   1. Constructs a mock client matching the vendor's call surface.
 *   2. Calls `tzun.attach(mockClient)`.
 *   3. Calls the wrapped method with `tzun_capture` in params.
 *   4. Asserts the underlying mock saw the call with `tzun_capture` stripped.
 *   5. Asserts `tzun.list({})` returned a single record (the capture).
 *
 * Plus one negative test: unknown client shape throws with informative
 * message naming every checked shape. The OpenRouter base-URL rule of the
 * `chat.completions.create` shape is covered in `openrouter.test.ts`.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';

describe('Tzun#attach — duck-type detection matrix', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('detects OpenAI shape (client.chat.completions.create)', async () => {
    const createSpy = jest.fn().mockResolvedValue({
      id: 'chatcmpl-x',
      model: 'gpt-4o-2024-08-06',
      choices: [],
    });
    const fakeClient = {
      chat: { completions: { create: createSpy } },
    };

    const wrapped = tzun.attach(fakeClient);
    expect(typeof wrapped.chat.completions.create).toBe('function');

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'b' },
    });

    // Underlying client must NOT have seen tzun_capture.
    expect(createSpy).toHaveBeenCalledTimes(1);
    const forwardedParams = createSpy.mock.calls[0][0];
    expect(forwardedParams.tzun_capture).toBeUndefined();
    expect(forwardedParams.model).toBe('gpt-4o-2024-08-06');

    const records = await tzun.list({});
    expect(records).toHaveLength(1);
    expect(records[0].envelope.payload.action).toBe('a');
  });

  it('detects Anthropic shape (client.messages.create)', async () => {
    const createSpy = jest.fn().mockResolvedValue({
      id: 'msg-x',
      content: [{ type: 'text', text: 'ok' }],
      model: 'claude-3-5-sonnet-20241022',
    });
    const fakeClient = { messages: { create: createSpy } };

    const wrapped = tzun.attach(fakeClient);
    await wrapped.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'b' },
    });

    expect(createSpy.mock.calls[0][0].tzun_capture).toBeUndefined();
    const records = await tzun.list({});
    expect(records).toHaveLength(1);
  });

  it('detects Bedrock shape (client.send + BedrockRuntimeClient ctor)', async () => {
    class BedrockRuntimeClient {
      send = jest.fn().mockResolvedValue({
        output: {
          message: { content: [{ text: 'ok' }] },
        },
      });
    }
    const fakeClient = new BedrockRuntimeClient();

    const wrapped = tzun.attach(fakeClient);
    expect(typeof wrapped.send).toBe('function');

    // Bedrock's send takes a command, not a kwargs object. We thread the
    // tzun_capture intent through a wrapper command object that carries
    // the kwarg alongside the SDK command shape.
    const fakeCommand = {
      input: { modelId: 'anthropic.claude-3-5-sonnet-20240620-v1:0', messages: [] },
      constructor: { name: 'ConverseCommand' },
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'b' },
    };
    await wrapped.send(fakeCommand);

    // The Bedrock send method takes a single command argument; the
    // tzun_capture is read off that command and stripped before forwarding.
    expect(fakeClient.send).toHaveBeenCalledTimes(1);
    const forwarded = fakeClient.send.mock.calls[0][0];
    expect(forwarded.tzun_capture).toBeUndefined();
    expect(forwarded.constructor.name).toBe('ConverseCommand');

    const records = await tzun.list({});
    expect(records).toHaveLength(1);
  });

  it('detects Vertex shape (client.generateContent)', async () => {
    const generateSpy = jest.fn().mockResolvedValue({
      response: {
        candidates: [{ content: { parts: [{ text: 'ok' }] } }],
      },
      modelId: 'gemini-1.5-pro-001',
    });
    const fakeClient = { generateContent: generateSpy };

    const wrapped = tzun.attach(fakeClient);
    await wrapped.generateContent({
      model: 'gemini-1.5-pro-001',
      contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'b' },
    });

    expect(generateSpy.mock.calls[0][0].tzun_capture).toBeUndefined();
    const records = await tzun.list({});
    expect(records).toHaveLength(1);
  });

  it('detects Azure AI shape (client.complete)', async () => {
    const completeSpy = jest.fn().mockResolvedValue({
      id: 'azure-x',
      model: 'mistral-large-2407',
      choices: [{ message: { content: 'ok' } }],
    });
    const fakeClient = { complete: completeSpy };

    const wrapped = tzun.attach(fakeClient);
    await wrapped.complete({
      model: 'mistral-large-2407',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'b' },
    });

    expect(completeSpy.mock.calls[0][0].tzun_capture).toBeUndefined();
    const records = await tzun.list({});
    expect(records).toHaveLength(1);
  });

  it('detects NVIDIA NIM shape with explicit { vendor: "nvidia-nim" } override', async () => {
    const createSpy = jest.fn().mockResolvedValue({
      id: 'chatcmpl-nim',
      model: 'meta/llama-3.1-405b-instruct',
      choices: [],
    });
    const fakeClient = { chat: { completions: { create: createSpy } } };

    const wrapped = tzun.attach(fakeClient, { vendor: 'nvidia-nim' });
    await wrapped.chat.completions.create({
      model: 'meta/llama-3.1-405b-instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'b' },
    });

    expect(createSpy.mock.calls[0][0].tzun_capture).toBeUndefined();
    const records = await tzun.list({});
    expect(records).toHaveLength(1);
    // aiSystemId derives from params.model when no override.
    expect(records[0].envelope.payload.aiSystemId).toBe('meta/llama-3.1-405b-instruct');
  });

  it('detects HF Inference shape (client.chatCompletion)', async () => {
    const chatSpy = jest.fn().mockResolvedValue({
      model: 'meta-llama/Meta-Llama-3-8B-Instruct',
      choices: [{ message: { content: 'ok' } }],
    });
    const fakeClient = { chatCompletion: chatSpy };

    const wrapped = tzun.attach(fakeClient);
    await wrapped.chatCompletion({
      model: 'meta-llama/Meta-Llama-3-8B-Instruct',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'a', reason: 'b' },
    });

    expect(chatSpy.mock.calls[0][0].tzun_capture).toBeUndefined();
    const records = await tzun.list({});
    expect(records).toHaveLength(1);
  });

  it('throws when client shape matches no known vendor', () => {
    expect(() => tzun.attach({ foo: () => undefined } as never)).toThrow(
      /Checked.*openai.*anthropic.*bedrock.*vertex.*azure-ai.*nvidia-nim.*hf-inference/,
    );
  });
});
