import { modelOf } from '../helpers/step-model';
import { singleModel } from '@tzun/engine';
/**
 * A capture that fails inside an `attach()`ed vendor call must be
 * OBSERVABLE.
 *
 * The wrapper contract is that a capture failure never throws and never
 * changes the response surface — `capture()` returns a `FailureRecord` and
 * the original vendor response still reaches the caller. That contract is
 * asserted here. What it does not license is emitting no signal at all: a
 * wrapper that discarded `capture()`'s return value would make a dropped
 * capture byte-for-byte indistinguishable from a stored one at the call site,
 * so the wrapper reports every drop on the SDK log sink.
 *
 * Most wrapper tests assert on `captureSpy.mock.calls[0][0]` — the
 * ARGUMENTS handed to `capture()`. This suite asserts on its RESULT and on
 * the log events, which is where silent loss shows.
 *
 * Coverage:
 *   - `{stored:false}` ⇒ `capture_failure` log; `{stored:true}` ⇒ none.
 *   - A REALISTIC Bedrock `InvokeModelCommandOutput` (genuine `Uint8Array`
 *     body) — the case plain-object fakes miss. `canonicalSerialize`
 *     rejects any non-plain prototype
 *     (`packages/engine/src/canonical.ts:84-91`), so every real
 *     InvokeModel capture is dropped as a `serialization_failure`.
 *   - A malformed `tzun_capture` (`readDecisionInput` does no shape
 *     validation) ⇒ `validation_failure`.
 *   - A descriptor-registration fault ⇒ `connector_hook_failure`, with the
 *     capture still proceeding on `aiBom: null` (documented behaviour).
 *   - No payload content in either event's fields.
 */

import { Tzun } from '../../../src/sdk/index';
import { __resetKnownModelsCacheForTests } from '../../../src/sdk/wrappers';
import type { CaptureResult } from '@tzun/engine';

type LogEvent = [string, Record<string, unknown>];

/** Sentinels: if any of these reach a log field, the failure log has leaked payload content. */
const REASON_SENTINEL = 'SENTINEL-human-reason-payload';
const ACTION_SENTINEL = 'SENTINEL-human-action-payload';
const OUTPUT_SENTINEL = 'SENTINEL-ai-output-payload';
const REVIEWER_SENTINEL = 'SENTINEL-reviewer-name';

function fakeOpenAI(modelInResponse = 'gpt-4o-2024-08-06') {
  return {
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue({
          id: 'chatcmpl-test',
          choices: [
            { index: 0, message: { role: 'assistant', content: OUTPUT_SENTINEL } },
          ],
          model: modelInResponse,
          system_fingerprint: 'fp_abc',
        }),
      },
    },
  };
}

/**
 * A Bedrock `InvokeModelCommandOutput` as the AWS SDK v3 actually returns
 * it: `body` is a `Uint8ArrayBlobAdapter` (a `Uint8Array` subclass) holding
 * the JSON response bytes, alongside the `$metadata` envelope. The
 * `tests/ts/wrappers/bedrock.test.ts` fake returns a plain object instead,
 * so it cannot see real InvokeModel traffic being dropped.
 */
class Uint8ArrayBlobAdapter extends Uint8Array {}

function realisticInvokeModelOutput(): Record<string, unknown> {
  const json = JSON.stringify({
    content: [{ type: 'text', text: OUTPUT_SENTINEL }],
    stop_reason: 'end_turn',
  });
  return {
    body: Uint8ArrayBlobAdapter.from(Buffer.from(json, 'utf8')),
    contentType: 'application/json',
    $metadata: {
      httpStatusCode: 200,
      requestId: '5b1f8c1e-0000-4000-8000-000000000000',
      attempts: 1,
      totalRetryDelay: 0,
    },
  };
}

class InvokeModelCommand {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
  constructor(public input: Record<string, unknown>) {}
}

class BedrockRuntimeClient {
  send = jest.fn().mockImplementation(async () => realisticInvokeModelOutput());
}

describe('attach() — capture failure is observable (not silent)', () => {
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

  const failures = () => events.filter(([e]) => e === 'capture_failure');
  const hookFailures = () => events.filter(([e]) => e === 'connector_hook_failure');

  it('a successful capture emits NO capture_failure event', async () => {
    const wrapped = tzun.attach(fakeOpenAI());

    const captureSpy = jest.spyOn(tzun, 'capture');
    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'risk acceptable' },
    });

    const result = (await captureSpy.mock.results[0].value) as CaptureResult;
    expect(result.stored).toBe(true);
    expect(failures()).toHaveLength(0);
  });

  it('a malformed tzun_capture is dropped as validation_failure AND logged', async () => {
    const client = fakeOpenAI();
    const wrapped = tzun.attach(client);
    const captureSpy = jest.spyOn(tzun, 'capture');

    // `readDecisionInput` (src/sdk/wrappers.ts) does no shape validation, so
    // this reaches `capture()` and is rejected there.
    const response = await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { action: '' },
    });

    // The wrapper contract: no throw, vendor response returned untouched.
    expect(response).toBe(await client.chat.completions.create.mock.results[0].value);

    const result = (await captureSpy.mock.results[0].value) as CaptureResult;
    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('validation_failure');

    expect(failures()).toHaveLength(1);
    expect(failures()[0][1]).toEqual({
      vendor: 'openai',
      failureType: 'validation_failure',
      aiSystemId: 'gpt-4o-2024-08-06',
      evidenceId: null,
      cloudErrorCode: 'invalid_action',
      retryable: undefined,
    });
  });

  it('descriptor_not_registered is logged with its failure type', async () => {
    const wrapped = tzun.attach(fakeOpenAI());

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: {
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        action: 'approved',
        reason: 'risk acceptable',
        aiBom: {
          modelDescriptorDigest: `sha256:${'0'.repeat(64)}`,
          vendorFingerprint: null,
          promptTemplate: null,
          inferenceParameters: null,
          infrastructure: null,
        },
      },
    });

    expect(failures()).toHaveLength(1);
    expect(failures()[0][1]).toMatchObject({
      vendor: 'openai',
      failureType: 'descriptor_not_registered',
    });
  });

  it('a REAL Bedrock InvokeModel response (Uint8Array body) is dropped — and says so', async () => {
    const client = new BedrockRuntimeClient();
    const wrapped = tzun.attach(client);
    const captureSpy = jest.spyOn(tzun, 'capture');

    const command = new InvokeModelCommand({
      modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
      body: JSON.stringify({ temperature: 0.4, max_tokens: 512 }),
    });
    (command as Record<string, unknown>).tzun_capture = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      action: 'approved',
      reason: 'risk acceptable',
    };

    const response = (await wrapped.send(command)) as Record<string, unknown>;

    // The response surface is untouched — the caller still gets the real
    // vendor output, blob body and all.
    expect(response.body).toBeInstanceOf(Uint8Array);

    // The AI-BOM was built fine (the connector only reads `params`) …
    expect(modelOf(captureSpy.mock.calls[0][0])).not.toBeNull();
    // … but the capture itself was dropped: `canonicalSerialize` rejects the
    // non-plain `Uint8Array` prototype, and `capture()` converts the throw
    // into a `serialization_failure`.
    const result = (await captureSpy.mock.results[0].value) as CaptureResult;
    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('serialization_failure');

    // Nothing was stored — the ledger has no record of this decision.
    expect(await tzun.list()).toHaveLength(0);

    // The whole point: the drop is not silent.
    expect(failures()).toHaveLength(1);
    expect(failures()[0][1]).toEqual({
      vendor: 'bedrock',
      failureType: 'serialization_failure',
      aiSystemId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
      evidenceId: null,
    });
  });

  it('logs no payload content — vendor, failure type and identifiers only', async () => {
    const wrapped = tzun.attach(new BedrockRuntimeClient());

    const command = new InvokeModelCommand({
      modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
      body: JSON.stringify({ temperature: 0.4 }),
    });
    (command as Record<string, unknown>).tzun_capture = {
      action: ACTION_SENTINEL,
      reason: REASON_SENTINEL,
      decider: { kind: 'human' as const, id: `acct:${REVIEWER_SENTINEL}`, agent: null, credential: null, freshness: null },
    };
    await wrapped.send(command);

    expect(failures()).toHaveLength(1);
    const serialized = JSON.stringify(events);
    for (const sentinel of [
      ACTION_SENTINEL,
      REASON_SENTINEL,
      REVIEWER_SENTINEL,
      OUTPUT_SENTINEL,
    ]) {
      expect(serialized).not.toContain(sentinel);
    }
    // Specifically: `diagnosticMetadata` (which echoes the caller's action and
    // reason on the validation path) is never forwarded to the sink.
    expect(failures()[0][1]).not.toHaveProperty('diagnosticMetadata');
  });

  it('a descriptor-registration fault logs connector_hook_failure and still captures', async () => {
    const storage = tzun.getStorage();
    jest
      .spyOn(storage, 'registerModelDescriptor' as never)
      .mockRejectedValue(new Error('SQLITE_BUSY: database is locked') as never);

    const wrapped = tzun.attach(fakeOpenAI());
    const captureSpy = jest.spyOn(tzun, 'capture');

    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'risk acceptable' },
    });

    // Documented behaviour: aiBom is null and the capture still runs — the
    // caller's decision outranks a missing AI-BOM.
    expect(captureSpy).toHaveBeenCalledTimes(1);
    expect(modelOf(captureSpy.mock.calls[0][0])).toBeNull();
    const result = (await captureSpy.mock.results[0].value) as CaptureResult;
    expect(result.stored).toBe(true);

    // But the AI-BOM loss is on the record.
    expect(hookFailures()).toHaveLength(1);
    expect(hookFailures()[0][1]).toEqual({ vendor: 'openai', errorName: 'Error' });
    // No message body — an error string can echo caller-supplied values.
    expect(JSON.stringify(events)).not.toContain('SQLITE_BUSY');
  });

  it('a clean run emits neither failure event', async () => {
    const wrapped = tzun.attach(fakeOpenAI());
    await wrapped.chat.completions.create({
      model: 'gpt-4o-2024-08-06',
      messages: [{ role: 'user', content: 'hi' }],
      tzun_capture: { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, action: 'approved', reason: 'risk acceptable' },
    });
    expect(failures()).toHaveLength(0);
    expect(hookFailures()).toHaveLength(0);
    expect(events.map(([e]) => e)).toContain('connector_auto_registration');
  });
});
