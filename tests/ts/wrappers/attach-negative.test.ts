/**
 * Negative tests for `tzun.attach()` and `tzun.hook()`.
 *
 * Covers the corner cases the per-vendor tests touch only lightly:
 * pass-through, explicit-null tzun_capture, kill-switch, standalone hook,
 * and the two error paths (unknown vendor / unknown client shape).
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';

function fakeOpenAI() {
  return {
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue({
          id: 'chatcmpl-x',
          choices: [],
          model: 'gpt-4o-2024-08-06',
        }),
      },
    },
  };
}

describe('attach() / hook() negative paths', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('attach() pass-through: call without tzun_capture does NOT capture', async () => {
    const client = fakeOpenAI();
    const wrapped = tzun.attach(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
    });

    const records = await tzun.list({});
    expect(records).toEqual([]);
  });

  it('attach() with explicit tzun_capture: null treated as absent', async () => {
    const client = fakeOpenAI();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: null,
    });

    expect(captureSpy).not.toHaveBeenCalled();
    const records = await tzun.list({});
    expect(records).toEqual([]);
  });

  it('attach() with emitAiBom:false skips capture even when tzun_capture present', async () => {
    const client = fakeOpenAI();
    const captureSpy = jest.spyOn(tzun, 'capture');
    const wrapped = tzun.attach(client, { emitAiBom: false });

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    expect(captureSpy).not.toHaveBeenCalled();
    const records = await tzun.list({});
    expect(records).toEqual([]);
  });

  it('hook() standalone does NOT wrap any client and does NOT trigger capture', async () => {
    const aiBom = await tzun.hook(
      'openai',
      {
        model: 'gpt-4o-2024-08-06',
        messages: [{ role: 'user', content: 'hi' }],
      },
      {
        id: 'chatcmpl-x',
        model: 'gpt-4o-2024-08-06',
        choices: [],
      },
    );
    expect(aiBom).not.toBeNull();
    const records = await tzun.list({});
    expect(records).toEqual([]);
  });

  it('hook() against unknown vendor throws with vendor list in message', async () => {
    await expect(tzun.hook('foo', {}, {})).rejects.toThrow(
      /openai.*anthropic.*bedrock.*vertex.*azure-ai.*nvidia-nim.*hf-inference/,
    );
  });

  it('attach() against unknown client shape throws with checked-shapes message', () => {
    expect(() => tzun.attach({} as never)).toThrow(
      /Checked.*openai.*anthropic.*bedrock.*vertex.*azure-ai.*nvidia-nim.*hf-inference/,
    );
  });
});
