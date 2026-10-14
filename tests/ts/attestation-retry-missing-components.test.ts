/**
 * retryPendingAttestations() requests only the
 * retry-obtainable components a record is missing, never replaces a token the
 * record already holds, and never anchors.
 *
 * A record that holds its timestamp and waits only for an anchor is 'pending',
 * but the retry cannot obtain an anchor: an anchor is
 * published for a batch of records. The retry leaves such a record alone. It
 * is not listed, not anchored, and its capture-time token and genTime stay.
 */
import { Tzun } from '../../src/sdk/index';
import type { CaptureInput } from '@tzun/engine';
import { mockTsaFetch } from './helpers/mock-tsa';
import { rewriteStoredEnvelope } from './helpers/tamper-store';

const decision: CaptureInput = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Meets all criteria',
};

describe('retryPendingAttestations() requests only the missing retry-obtainable components', () => {
  let savedFetch: typeof globalThis.fetch;
  let tsaUp: boolean;
  let tsaCalls: number;
  let tzun: Tzun;

  beforeEach(async () => {
    savedFetch = globalThis.fetch;
    tsaUp = true;
    tsaCalls = 0;

    const tsa = mockTsaFetch();
    globalThis.fetch = jest.fn(async (...args: Parameters<typeof fetch>) => {
      tsaCalls++;
      if (!tsaUp) throw new Error('TSA unreachable');
      return tsa(...args);
    }) as unknown as typeof fetch;

    tzun = await Tzun.init({
      mode: 'dev',
      attestation: {
        deferrable: ['timestamp'],
        timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
      },
    });
  });

  afterEach(async () => {
    await tzun.close();
    globalThis.fetch = savedFetch;
    jest.restoreAllMocks();
  });

  it('a record waiting only for an anchor is not listed, not anchored, and keeps its token and genTime', async () => {
    const captured = await tzun.capture(decision);
    const evidenceId = captured.envelope.payload.evidenceId;
    const captureToken = captured.envelope.nonRepudiation.rfc3161Token;
    const captureGenTime = captured.envelope.nonRepudiation.rfc3161Metadata?.genTime;
    expect(captureToken).toBeDefined();
    expect(captureGenTime).toBeDefined();
    // Parked the way a writer that expects an anchor stores it: timestamped,
    // no anchor, 'pending'.
    await tzun.getStorage().updateAttestation(evidenceId, {}, 'pending');

    const tsaCallsBefore = tsaCalls;
    const result = await tzun.retryPendingAttestations();

    expect(result).toEqual({ attempted: 0, succeeded: 0, failed: 0, details: [] });
    expect(tsaCalls).toBe(tsaCallsBefore);

    const after = await tzun.getStorage().retrieve(evidenceId);
    expect(after!.nonRepudiation.rfc3161Token).toBe(captureToken);
    expect(after!.nonRepudiation.rfc3161Metadata?.genTime).toBe(captureGenTime);
    expect(after!.nonRepudiation.anchor).toBeUndefined();
    expect(after!.attestationStatus).toBe('pending');
  });

  it('a retry that obtains nothing writes nothing and reports what is still missing', async () => {
    tsaUp = false;
    const captured = await tzun.capture(decision);
    const evidenceId = captured.envelope.payload.evidenceId;
    expect(captured.envelope.attestationStatus).toBe('pending');

    const update = jest.spyOn(tzun.getStorage(), 'updateAttestation');
    const tsaCallsBefore = tsaCalls;
    const result = await tzun.retryPendingAttestations();

    expect(tsaCalls).toBeGreaterThan(tsaCallsBefore);
    expect(result).toMatchObject({ attempted: 1, succeeded: 0, failed: 1 });
    expect(result.details[0]).toMatchObject({
      evidenceId,
      success: false,
      stillMissing: ['timestamp'],
    });
    expect(update).not.toHaveBeenCalled();

    const after = await tzun.getStorage().retrieve(evidenceId);
    expect(after!.nonRepudiation.rfc3161Token).toBeUndefined();
    expect(after!.attestationStatus).toBe('pending');
  });

  // An empty token is a missing one to the status rule, the queue and the
  // fill rule alike. The record is listed, the retry's token replaces the empty
  // one, and success is reported only because the token is really stored.
  it('a record whose stored token is empty is retried and gets a real token', async () => {
    const captured = await tzun.capture(decision);
    const evidenceId = captured.envelope.payload.evidenceId;
    await rewriteStoredEnvelope(tzun.getStorage(), evidenceId, (env) => {
      env.nonRepudiation = { rfc3161Token: '' };
      env.attestationStatus = 'pending';
    });

    const result = await tzun.retryPendingAttestations();
    expect(result).toMatchObject({ attempted: 1, succeeded: 1, failed: 0 });

    const after = await tzun.getStorage().retrieve(evidenceId);
    expect(after!.nonRepudiation.rfc3161Token).toBeTruthy();
    expect(after!.attestationStatus).toBe('partial');
    expect(await tzun.getStorage().listByMissingObtainable(['timestamp'])).toEqual([]);
  });

  it('a record missing its timestamp gets one, leaves the queue, and nothing is anchored', async () => {
    tsaUp = false;
    const captured = await tzun.capture(decision);
    const evidenceId = captured.envelope.payload.evidenceId;

    tsaUp = true;
    const result = await tzun.retryPendingAttestations();
    expect(result).toMatchObject({ attempted: 1, succeeded: 1, failed: 0 });
    expect(result.details[0]).toEqual({ evidenceId, success: true });

    const after = await tzun.getStorage().retrieve(evidenceId);
    expect(after!.nonRepudiation.rfc3161Token).toBeDefined();
    expect(after!.attestationStatus).toBe('partial');
    expect(await tzun.getStorage().listByMissingObtainable(['timestamp'])).toEqual([]);
  });
});
