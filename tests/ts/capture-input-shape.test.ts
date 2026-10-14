/**
 * capture() refuses the input shapes the platform refuses.
 *
 * `aiOutput` is a plain object; `action` is 1 to 128 printable ASCII
 * characters with no leading or trailing space; `reason` is 1 to 16,384 UTF-16
 * code units; `aiSystemId`, when given, is a non-empty string that is not a
 * reserved `tzun:` id; `decider` is required; the 0.7 names are refused. A
 * refused capture reports the way every other refused capture does —
 * `stored: false`, a `validation_failure` FailureRecord naming the field and
 * the rule's code, the failure persisted, and nothing written to the chain.
 */
import { Tzun } from '../../src/sdk/index';
import type { CaptureInput, FailureRecord } from '@tzun/engine';

const valid = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Meets all criteria',
};

/** Build an input the type system would refuse, the way a JSON body can. */
function shape(overrides: Record<string, unknown>, omit: string[] = []): CaptureInput {
  const input: Record<string, unknown> = { ...valid, ...overrides };
  for (const key of omit) delete input[key];
  return input as unknown as CaptureInput;
}

const refused: Array<[string, CaptureInput, string, string]> = [
  ['aiOutput as a string', shape({ aiOutput: 'approve' }), 'aiOutput', 'invalid_ai_output'],
  ['aiOutput as an array', shape({ aiOutput: [{ recommendation: 'approve' }] }), 'aiOutput', 'invalid_ai_output'],
  ['aiOutput missing', shape({}, ['aiOutput']), 'aiOutput', 'invalid_ai_output'],
  ['aiOutput null', shape({ aiOutput: null }), 'aiOutput', 'invalid_ai_output'],
  ['aiOutput a class instance', shape({ aiOutput: new Date(0) }), 'aiOutput', 'invalid_ai_output'],
  ['action a number', shape({ action: 123 }), 'action', 'invalid_action'],
  ['action an object', shape({ action: { value: 'approved' } }), 'action', 'invalid_action'],
  ['action empty', shape({ action: '' }), 'action', 'invalid_action'],
  ['action missing', shape({}, ['action']), 'action', 'invalid_action'],
  ['action with a trailing space', shape({ action: 'approved ' }), 'action', 'invalid_action'],
  ['action outside printable ASCII', shape({ action: 'approuvé' }), 'action', 'invalid_action'],
  ['reason a number', shape({ reason: 123 }), 'reason', 'invalid_reason'],
  ['reason an array', shape({ reason: ['because'] }), 'reason', 'invalid_reason'],
  ['reason empty', shape({ reason: '' }), 'reason', 'invalid_reason'],
  ['aiSystemId a number', shape({ aiSystemId: 123 }), 'aiSystemId', 'invalid_ai_system_id'],
  ['aiSystemId empty', shape({ aiSystemId: '' }), 'aiSystemId', 'invalid_ai_system_id'],
  ['aiSystemId a reserved system id', shape({ aiSystemId: 'tzun:link' }), 'aiSystemId', 'reserved_ai_system_id'],
  ['decider missing', shape({}, ['decider']), 'decider', 'missing_members'],
  ['decider with an unknown member', shape({ decider: { kind: 'human', id: 'acct:u-1', name: 'x' } }), 'decider.name', 'unknown_members'],
  ['decider with an email address for an id', shape({ decider: { kind: 'human', id: 'acct:jane@acme.example' } }), 'decider.id', 'invalid_identifier'],
  ['humanAction (renamed)', shape({ humanAction: 'approved' }), 'humanAction', 'renamed_field'],
  ['humanReason (renamed)', shape({ humanReason: 'ok' }), 'humanReason', 'renamed_field'],
  ['reviewer (renamed)', shape({ reviewer: 'u-1' }), 'reviewer', 'renamed_field'],
  ['a top-level aiBom (moved)', shape({ aiBom: null }), 'aiBom', 'moved_field'],
  ['a top-level lineage (moved)', shape({ lineage: null }), 'lineage', 'moved_field'],
  ['links: [] (no link is null)', shape({ links: [] }), 'links', 'empty_links'],
];
describe('capture() refuses input shapes the platform refuses', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev' });
  });

  afterEach(async () => {
    await tzun.close();
  });

  it.each(refused)('%s is refused as a validation_failure', async (_label, input, field, code) => {
    const storeFailure = jest.spyOn(tzun.getStorage(), 'storeFailure');

    const result = await tzun.capture(input);

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('validation_failure');
    expect(result.failure?.diagnosticMetadata.field).toBe(field);
    expect(result.failure?.diagnosticMetadata.reason).toBe(code);
    expect(result.failure?.diagnosticMetadata.code).toBe(code);
    expect(typeof result.failure?.diagnosticMetadata.message).toBe('string');

    // Reported the way every other refused capture is: the failure is persisted.
    expect(storeFailure).toHaveBeenCalledTimes(1);
    expect((storeFailure.mock.calls[0][0] as FailureRecord).failureType).toBe(
      'validation_failure',
    );

    // Nothing reached the chain.
    expect(await tzun.list()).toHaveLength(0);
  });

  it('a refused capture does not consume a sequence number', async () => {
    await tzun.capture(shape({ action: 123 }));
    const ok = await tzun.capture(valid);
    expect(ok.stored).toBe(true);
    expect(ok.envelope.payload.sequenceNumber).toBe(1);
  });

  it('the failure names the provided type, not the provided value', async () => {
    const result = await tzun.capture(shape({ action: 123 }));
    expect(result.failure?.diagnosticMetadata.providedType).toBe('number');
    expect(JSON.stringify(result.failure?.diagnosticMetadata)).not.toContain('123');
  });

  it('a missing input object is refused, not thrown', async () => {
    const result = await tzun.capture(undefined as unknown as CaptureInput);
    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('validation_failure');
    expect(result.failure?.diagnosticMetadata.field).toBe('input');
  });

  it('valid input is still stored, with aiSystemId optional', async () => {
    const withoutId = await tzun.capture(valid);
    expect(withoutId.stored).toBe(true);
    expect(withoutId.envelope.payload.aiSystemId).toBe('default');

    const withId = await tzun.capture({ ...valid, aiSystemId: 'credit-model' });
    expect(withId.stored).toBe(true);
    expect(withId.envelope.payload.aiSystemId).toBe('credit-model');
  });

  it('an aiOutput with no prototype is a plain object', async () => {
    const aiOutput = Object.assign(Object.create(null), { recommendation: 'approve' });
    const result = await tzun.capture({ ...valid, aiOutput });
    expect(result.stored).toBe(true);
  });

  it.each(refused)(
    'prepareAssertionChallenge() refuses %s too',
    async (_label, input, field) => {
      await expect(tzun.prepareAssertionChallenge(input)).rejects.toThrow(field);
    },
  );

  it('the failure names the field and the rule, never the value', async () => {
    const result = await tzun.capture(shape({ reason: 'x'.repeat(16_385) }));
    expect(result.failure?.diagnosticMetadata).toMatchObject({ field: 'reason', code: 'invalid_reason' });
    expect(JSON.stringify(result.failure?.diagnosticMetadata)).not.toContain('xxxx');
  });
});
