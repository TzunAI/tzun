/**
 * `emitAiBom: false` drops captures, and says so on the SDK log sink.
 *
 * The option name reads like "skip the descriptor catalog round-trip", but the
 * branch it controls is a capture kill-switch: with it set, a call carrying
 * `tzun_capture` is forwarded to the vendor and NO evidence is recorded. Every
 * other way a capture can be lost (connector throw, storage fault, capture()
 * returning `{stored:false}`) emits on the SDK log sink. If this branch
 * emitted nothing, an operator who flipped it during an incident and forgot
 * to revert would get a month of unrecorded decisions with no telemetry
 * saying so.
 *
 * The assertions are on the OUTCOME visible to an embedder — what arrives on
 * `TzunConfig.onLog` — not on the internal call that produces it.
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

describe('emitAiBom:false observability', () => {
  let tzun: Tzun;
  let events: Array<{ event: string; fields: Record<string, unknown> }>;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    events = [];
    tzun = await Tzun.init({
      onLog: (event, fields) => events.push({ event, fields }),
    });
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('emits capture_skipped when a tzun_capture call is dropped by the kill-switch', async () => {
    const client = fakeOpenAI();
    const wrapped = tzun.attach(client, { emitAiBom: false });

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    // The evidence really is gone — the log is the ONLY signal, so it has to be
    // there.
    expect(await tzun.list({})).toEqual([]);

    const skipped = events.filter((e) => e.event === 'capture_skipped');
    expect(skipped).toHaveLength(1);
    expect(skipped[0].fields).toEqual({
      vendor: 'openai',
      reason: 'emitAiBom:false',
    });
  });

  it('logs no payload content with the skip event', async () => {
    const client = fakeOpenAI();
    const wrapped = tzun.attach(client, { emitAiBom: false });

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'SECRET-PROMPT' }],
      tzun_capture: {
        action: 'approved',
        reason: 'SECRET-REASON',
        decider: { kind: 'human' as const, id: 'acct:SECRET-REVIEWER', agent: null, credential: null, freshness: null },
      },
    });

    const serialised = JSON.stringify(events);
    expect(serialised).not.toContain('SECRET-PROMPT');
    expect(serialised).not.toContain('SECRET-REASON');
    expect(serialised).not.toContain('SECRET-REVIEWER');
  });

  it('stays silent for an ordinary pass-through call with no tzun_capture', async () => {
    // A call that never asked to be captured is not a skip. If this were noisy
    // the event would be worthless — every un-annotated vendor call under a
    // kill-switched client would emit one.
    const client = fakeOpenAI();
    const wrapped = tzun.attach(client, { emitAiBom: false });

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
    });

    expect(events.filter((e) => e.event === 'capture_skipped')).toEqual([]);
  });

  it('stays silent on the normal capturing path', async () => {
    const client = fakeOpenAI();
    const wrapped = tzun.attach(client);

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'ok' },
    });

    expect(events.filter((e) => e.event === 'capture_skipped')).toEqual([]);
    expect((await tzun.list({})).length).toBe(1);
  });
});
