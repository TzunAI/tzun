/**
 * A `prepared` capture's identity is checked before it becomes the record's
 * identity.
 *
 * `capture(input, { prepared })` takes the record's `evidenceId` and
 * `capturedAt` from `prepared` (they are hashed fields, and the reviewer's
 * ceremony signed a digest over them). Neither was checked: any string became
 * the stored evidenceId, and any capturedAt was stored as the record's time.
 *
 * The rules are the hosted service's, from its capture path: the evidenceId is
 * a v4 UUID (`EVIDENCE_ID_RE`), and capturedAt is an ISO-8601 date-time that is not more
 * than five minutes in the future (`validateCapturedAtClaim`). A violation is a
 * `validation_failure` naming the field, reported before a sequence number is
 * taken, never a throw.
 */
import { Tzun, type PreparedAssertionChallenge } from '../../src/sdk/index';
import {
  canonicalSerialize,
  computeDigest,
  SchemaRegistry,
  webauthnChallengeForDigest,
  type CaptureInput,
  type FailureRecord,
} from '@tzun/engine';

const decision: CaptureInput = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Meets all criteria',
};

const HASHED = new SchemaRegistry().get('v1.0')!.hashedFieldSet;

/**
 * A `prepared` value carrying a chosen identity AND the digest of the record
 * that identity produces at the prepared chain position, so the capture's
 * moved-record check (digest vs prepared.digest) passes. This is what a caller
 * who builds `prepared` by hand, rather than taking it from
 * prepareAssertionChallenge(), hands capture().
 */
function forge(
  base: PreparedAssertionChallenge,
  overrides: Record<string, unknown>,
): PreparedAssertionChallenge {
  const identity = { evidenceId: base.evidenceId, capturedAt: base.capturedAt, ...overrides };
  const payload = {
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    links: null,
    evidenceId: identity.evidenceId,
    schemaVersion: 'v1.0',
    aiSystemId: 'default',
    aiOutput: decision.aiOutput,
    action: decision.action,
    reason: decision.reason,
    capturedAt: identity.capturedAt,
    sequenceNumber: base.sequenceNumber,
    contributions: null,
  };
  const digest = computeDigest(canonicalSerialize(payload, HASHED));
  return {
    ...base,
    ...identity,
    digest,
    challenge: webauthnChallengeForDigest(digest),
  } as unknown as PreparedAssertionChallenge;
}

describe('a prepared capture identity is checked', () => {
  let tzun: Tzun;
  let prepared: PreparedAssertionChallenge;

  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev' });
    prepared = await tzun.prepareAssertionChallenge(decision);
  });

  afterEach(async () => {
    await tzun.close();
  });

  it('a prepared identity from prepareAssertionChallenge() is accepted', async () => {
    const result = await tzun.capture(decision, { prepared });
    expect(result.stored).toBe(true);
    expect(result.envelope.payload.evidenceId).toBe(prepared.evidenceId);
    expect(result.envelope.payload.capturedAt).toBe(prepared.capturedAt);
  });

  it('a forged prepared identity that satisfies the rules is accepted', async () => {
    // The forge helper itself is sound: an identity that obeys both rules and
    // carries its own digest stores, so the refusals below are the rules.
    const pastIso = new Date(Date.now() - 60 * 1000).toISOString();
    const result = await tzun.capture(decision, { prepared: forge(prepared, { capturedAt: pastIso }) });
    expect(result.stored).toBe(true);
    expect(result.envelope.payload.capturedAt).toBe(pastIso);
  });

  const refused: Array<[string, Record<string, unknown>, string, string]> = [
    ['a non-UUID evidenceId', { evidenceId: 'inv-0001' }, 'prepared.evidenceId', 'invalid_evidence_id'],
    [
      'a v1 UUID evidenceId',
      { evidenceId: 'c232ab00-9414-11ec-b3c8-9f6bdeced846' },
      'prepared.evidenceId',
      'invalid_evidence_id',
    ],
    ['an empty evidenceId', { evidenceId: '' }, 'prepared.evidenceId', 'invalid_evidence_id'],
    ['a numeric evidenceId', { evidenceId: 123 }, 'prepared.evidenceId', 'invalid_evidence_id'],
    ['an unparsable capturedAt', { capturedAt: 'yesterday' }, 'prepared.capturedAt', 'invalid_captured_at'],
    ['a date-only capturedAt', { capturedAt: '2026-09-18' }, 'prepared.capturedAt', 'invalid_captured_at'],
    [
      'a capturedAt with no zone',
      { capturedAt: '2026-09-18T10:00:00' },
      'prepared.capturedAt',
      'invalid_captured_at',
    ],
    [
      'an impossible capturedAt',
      { capturedAt: '2026-13-45T10:00:00Z' },
      'prepared.capturedAt',
      'invalid_captured_at',
    ],
    [
      'a capturedAt an hour in the future',
      { capturedAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() },
      'prepared.capturedAt',
      'invalid_captured_at',
    ],
    ['a numeric capturedAt', { capturedAt: Date.now() }, 'prepared.capturedAt', 'invalid_captured_at'],
  ];

  it.each(refused)('%s is a validation_failure', async (_label, overrides, field, code) => {
    const storeFailure = jest.spyOn(tzun.getStorage(), 'storeFailure');
    const store = jest.spyOn(tzun.getStorage(), 'store');

    const result = await tzun.capture(decision, { prepared: forge(prepared, overrides) });

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('validation_failure');
    expect(result.failure?.diagnosticMetadata).toMatchObject({ field, code });
    expect(storeFailure).toHaveBeenCalledTimes(1);
    expect((storeFailure.mock.calls[0][0] as FailureRecord).failureType).toBe('validation_failure');
    // Refused before anything was built or stored.
    expect(store).not.toHaveBeenCalled();
  });

  it('a capturedAt more than five minutes ahead is refused as future_dated', async () => {
    const result = await tzun.capture(decision, {
      prepared: forge(prepared, { capturedAt: new Date(Date.now() + 6 * 60 * 1000).toISOString() }),
    });
    expect(result.failure?.diagnosticMetadata).toMatchObject({
      field: 'prepared.capturedAt',
      code: 'invalid_captured_at',
    });
    expect(String(result.failure?.diagnosticMetadata.message)).toMatch(/future/);
  });

  it('a refused prepared identity does not consume a sequence number', async () => {
    await tzun.capture(decision, { prepared: forge(prepared, { evidenceId: 'inv-0001' }) });
    const ok = await tzun.capture(decision);
    expect(ok.stored).toBe(true);
    expect(ok.envelope.payload.sequenceNumber).toBe(1);
  });

  it('a prepared value that is not an object is a validation_failure', async () => {
    const result = await tzun.capture(decision, {
      prepared: 'prepared' as unknown as PreparedAssertionChallenge,
    });
    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('validation_failure');
    expect(result.failure?.diagnosticMetadata.field).toBe('prepared');
  });
});
