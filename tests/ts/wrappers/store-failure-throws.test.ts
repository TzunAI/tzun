/**
 * A failure-record write that throws must not escape `capture()`.
 *
 * `capture()` persists a FailureRecord on every path that decides the
 * capture has failed, including the validation path and the catch block
 * around `store()`. SQLite and Postgres `storeFailure` are real writes that
 * throw on any DB error, which is exactly the moment `store()` has just
 * thrown. If that throw escaped, then during a 20-second Postgres restart
 * every `wrapped.chat.completions.create({..., tzun_capture})` would reject
 * with a raw `pg`/`SQLITE_*` error AFTER OpenAI had already answered,
 * destroying the model output and the human decision along with the
 * evidence — breaking the wrapper contract that a capture failure never
 * throws and never changes the response surface.
 *
 * capture-failure-log.test.ts covers the log events with storage healthy;
 * this file makes `storeFailure` reject.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { CaptureResult } from '@tzun/engine';

type LogEvent = [string, Record<string, unknown>];

const OUTPUT_SENTINEL = 'the-vendor-answer-we-must-not-lose';
const DB_ERROR = 'connect ECONNREFUSED 10.0.0.5:5432';

function fakeOpenAI() {
  return {
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue({
          id: 'chatcmpl-test',
          choices: [
            { index: 0, message: { role: 'assistant', content: OUTPUT_SENTINEL } },
          ],
          model: 'gpt-4o-2024-08-06',
          system_fingerprint: 'fp_abc',
        }),
      },
    },
  };
}

describe('a database outage must not destroy the vendor response', () => {
  let events: LogEvent[];
  let tzun: Tzun;

  beforeEach(async () => {
    __resetKnownModelsCacheForTests();
    events = [];
    tzun = await Tzun.init({
      onLog: (event, fields) => events.push([event, fields]),
    });
  });

  afterEach(async () => {
    await tzun.close();
  });

  const named = (name: string) => events.filter(([e]) => e === name);

  /** Simulate the DB being down for writes, as SQLite/Postgres really behave. */
  function breakStorageWrites(alsoBreakStore: boolean): void {
    const storage = tzun.getStorage();
    jest
      .spyOn(storage, 'storeFailure')
      .mockRejectedValue(new Error(DB_ERROR));
    if (alsoBreakStore) {
      jest.spyOn(storage, 'store').mockRejectedValue(new Error(DB_ERROR));
    }
  }

  it('(a) validation path: capture() resolves {stored:false} when storeFailure throws', async () => {
    breakStorageWrites(false);

    const result = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys',
      aiOutput: { answer: 'x' },
      action: '',
      reason: '',
    });

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('validation_failure');
    // The unpersistable failure record is itself logged — the swallow is not
    // silent, or containing the throw would just move the blind spot.
    expect(named('failure_record_unpersisted')).toHaveLength(1);
    expect(named('failure_record_unpersisted')[0][1]).toMatchObject({
      failureType: 'validation_failure',
    });
  });

  it('(b) store-failed path: the storeFailure inside the catch must not re-throw', async () => {
    breakStorageWrites(true);

    const result = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys',
      aiOutput: { answer: 'x' },
      action: 'approved',
      reason: 'ok',
    });

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('serialization_failure');
    expect(named('failure_record_unpersisted')).toHaveLength(1);
  });

  it('(c) attach(): the vendor response still reaches the caller during an outage', async () => {
    const client = fakeOpenAI();
    const wrapped = tzun.attach(client);
    breakStorageWrites(true);

    const response = await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'risk acceptable' },
    });

    // The wrapper contract: the response surface is unchanged.
    expect(response.choices[0].message.content).toBe(OUTPUT_SENTINEL);
    expect(client.chat.completions.create).toHaveBeenCalledTimes(1);
    // ...and the dropped capture is still reported.
    expect(named('capture_failure')).toHaveLength(1);
  });

  it('(d) attach(): a capture() that throws outright is contained, not propagated', async () => {
    const client = fakeOpenAI();
    const wrapped = tzun.attach(client);
    jest
      .spyOn(tzun, 'capture')
      .mockRejectedValue(new Error('unexpected internal fault'));

    const response = await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'risk acceptable' },
    });

    expect(response.choices[0].message.content).toBe(OUTPUT_SENTINEL);
    const logged = named('capture_failure');
    expect(logged).toHaveLength(1);
    expect(logged[0][1]).toMatchObject({ failureType: 'capture_threw' });
  });

  it('(e) control: with storage healthy, the failure record IS persisted', async () => {
    const storage = tzun.getStorage();
    const spy = jest.spyOn(storage, 'storeFailure');

    const result: CaptureResult = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys',
      aiOutput: { answer: 'x' },
      action: '',
      reason: '',
    });

    expect(result.stored).toBe(false);
    expect(spy).toHaveBeenCalledTimes(1);
    // No swallow happened, so no unpersisted log — this guards against
    // avoiding the throw by simply not writing failure records.
    expect(named('failure_record_unpersisted')).toHaveLength(0);
  });
});
