import { Tzun, RetryResult } from '../../src/sdk/index';
import { CaptureInput } from '@tzun/engine';
import { mockTsaFetch } from './helpers/mock-tsa';

describe('Pending Attestation Retry', () => {
  const validInput: CaptureInput = {
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    aiOutput: { recommendation: 'approve', confidence: 0.92 },
    action: 'approved',
    reason: 'Meets all criteria',
  };

  it('retryPendingAttestations method exists on Tzun', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    expect(typeof tzun.retryPendingAttestations).toBe('function');
  });

  it('returns zero counts when no pending records exist', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });

    const result = await tzun.retryPendingAttestations();

    expect(result).toEqual({
      attempted: 0,
      succeeded: 0,
      failed: 0,
      details: [],
    });
  });

  it('retries a pending record: mock fetch fails first, succeeds on retry', async () => {
    const savedFetch = globalThis.fetch;
    try {
      // Single mock: first call (during capture) fails, second call (during retry) succeeds.
      // The RFC3161Client captures globalThis.fetch at construction time, so we must use
      // a single mock reference that changes behavior across calls.
      const mockFetch = jest.fn()
        .mockRejectedValueOnce(new Error('network error'))
        .mockImplementation(mockTsaFetch());

      globalThis.fetch = mockFetch;

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          deferrable: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      // Capture with failing timestamp. A configured-but-failed component
      // lands as 'pending' straight out of capture(), so the retry below
      // exercises the path a real TSA outage takes rather than a row flipped
      // to 'pending' by hand.
      const captureResult = await tzun.capture(validInput);
      expect(captureResult.stored).toBe(true);
      expect(captureResult.envelope.attestationStatus).toBe('pending');
      expect(captureResult.envelope.nonRepudiation.rfc3161Token).toBeUndefined();

      const evidenceId = captureResult.envelope.payload.evidenceId;
      const originalDigest = captureResult.envelope.integrity.canonicalDigest;
      const originalPayload = { ...captureResult.envelope.payload };

      // Not set by hand: capture() already stored it as 'pending'.
      const storage = tzun.getStorage();

      // Verify it's pending
      const pendingEnvelope = await storage.retrieve(evidenceId);
      expect(pendingEnvelope!.attestationStatus).toBe('pending');

      // Retry pending attestations (mockFetch will now succeed)
      const retryResult = await tzun.retryPendingAttestations();

      expect(retryResult.attempted).toBe(1);
      expect(retryResult.succeeded).toBe(1);
      expect(retryResult.failed).toBe(0);
      expect(retryResult.details).toHaveLength(1);
      expect(retryResult.details[0]).toEqual({
        evidenceId,
        success: true,
      });

      // Verify the envelope was updated: artifact added, status updated
      const updatedEnvelope = await storage.retrieve(evidenceId);
      expect(updatedEnvelope!.nonRepudiation.rfc3161Token).toBeDefined();
      expect(updatedEnvelope!.attestationStatus).toBe('partial');

      // Payload and digest remain unchanged
      expect(updatedEnvelope!.payload).toEqual(originalPayload);
      expect(updatedEnvelope!.integrity.canonicalDigest).toBe(originalDigest);
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it('failed retry leaves status as pending', async () => {
    const savedFetch = globalThis.fetch;
    try {
      // All calls fail — both during capture and during retry.
      // The RFC3161Client captures globalThis.fetch at construction time.
      globalThis.fetch = jest.fn().mockRejectedValue(new Error('network error'));

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          deferrable: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      const captureResult = await tzun.capture(validInput);
      expect(captureResult.stored).toBe(true);

      const evidenceId = captureResult.envelope.payload.evidenceId;

      // Set to pending
      const storage = tzun.getStorage();
      await storage.updateAttestation(evidenceId, {}, 'pending');

      // Retry — fetch still fails, so no new artifacts are obtained
      const retryResult = await tzun.retryPendingAttestations();

      expect(retryResult.attempted).toBe(1);
      expect(retryResult.succeeded).toBe(0);
      expect(retryResult.failed).toBe(1);
      expect(retryResult.details[0].success).toBe(false);
      expect(retryResult.details[0].error).toBeDefined();

      // Status should still be pending
      const envelope = await storage.retrieve(evidenceId);
      expect(envelope!.attestationStatus).toBe('pending');
    } finally {
      globalThis.fetch = savedFetch;
    }
  });
});
