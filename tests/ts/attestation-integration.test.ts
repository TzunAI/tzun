import { Tzun } from '../../src/sdk/index';
import { CaptureInput } from '@tzun/engine';
import { mockTsaFetch } from './helpers/mock-tsa';

describe('Attestation Integration: Orchestrator Lifecycle', () => {
  describe('init', () => {
    it('dev mode without attestation does not throw', async () => {
      const tzun = await Tzun.init({ mode: 'dev' });
      expect(tzun).toBeDefined();
      expect(tzun.getMode()).toBe('dev');
    });

    it('dev mode with explicit attestation opt-in (timestamp config)', async () => {
      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          require: ['timestamp'],
          timestamp: {
            rfc3161Url: 'https://freetsa.org/tsr',
          },
        },
      });
      expect(tzun).toBeDefined();
      expect(tzun.getMode()).toBe('dev');
    });

    it('local mode with require: [] throws', async () => {
      await expect(
        Tzun.init({
          mode: 'local',
          dbPath: ':memory:',
          attestation: { require: [] },
        }),
      ).rejects.toThrow('Production modes must obtain an RFC 3161 timestamp for every record');
    });

    it('cloud mode with require excluding timestamp throws', async () => {
      await expect(
        Tzun.init({
          mode: 'cloud',
          apiKey: 'tzun_test_key',
          attestation: {
            require: ['webauthn'],
          },
        }),
      ).rejects.toThrow('Production modes must obtain an RFC 3161 timestamp for every record');
    });
  });

  describe('close', () => {
    it('close() resolves without error in dev mode', async () => {
      const tzun = await Tzun.init({ mode: 'dev' });
      await expect(tzun.close()).resolves.toBeUndefined();
    });

    it('double close is idempotent', async () => {
      const tzun = await Tzun.init({ mode: 'dev' });
      await tzun.close();
      await expect(tzun.close()).resolves.toBeUndefined();
    });
  });
});

describe('Attestation Integration: Capture Flow', () => {
  const validInput: CaptureInput = {
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    aiOutput: { recommendation: 'approve', confidence: 0.92 },
    action: 'approved',
    reason: 'Meets all criteria',
  };

  it('dev mode capture: attestationStatus is none, no artifacts', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    const result = await tzun.capture(validInput);

    expect(result.stored).toBe(true);
    expect(result.envelope.attestationStatus).toBe('none');
    expect(result.envelope.nonRepudiation).toEqual({});
  });

  it('dev mode with timestamp opt-in: envelope has timestamp artifact', async () => {
    const savedFetch = globalThis.fetch;
    try {
      // Mock fetch for RFC 3161 timestamp request
      globalThis.fetch = mockTsaFetch() as unknown as typeof fetch;

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          require: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      const result = await tzun.capture(validInput);

      expect(result.stored).toBe(true);
      expect(result.envelope.attestationStatus).toBe('partial');
      expect(result.envelope.nonRepudiation.rfc3161Token).toBeDefined();
      expect(typeof result.envelope.nonRepudiation.rfc3161Token).toBe('string');
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it('required attestation failure aborts capture with attestation_failure', async () => {
    const savedFetch = globalThis.fetch;
    try {
      // Mock fetch to simulate timestamp failure
      globalThis.fetch = jest.fn().mockRejectedValue(new Error('network error'));

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          require: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      const result = await tzun.capture(validInput);

      expect(result.stored).toBe(false);
      expect(result.failure).toBeDefined();
      expect(result.failure!.failureType).toBe('attestation_failure');
      expect(result.failure!.diagnosticMetadata.missingServices).toContain('timestamp');
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it('deferrable attestation failure stores the envelope pending', async () => {
    const savedFetch = globalThis.fetch;
    try {
      // Mock fetch to simulate timestamp failure
      globalThis.fetch = jest.fn().mockRejectedValue(new Error('network error'));

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          deferrable: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      const result = await tzun.capture(validInput);

      // Capture should succeed despite timestamp failure (it's deferrable).
      //
      // A configured component that produced no artifact is 'pending', not
      // 'none'. 'none' is the status for "nothing was asked for", and it is
      // the one status `retryPendingAttestations()` never picks up, so a
      // capture taken during a TSA outage and recorded as 'none' would stay
      // un-timestamped forever.
      expect(result.stored).toBe(true);
      expect(result.envelope.attestationStatus).toBe('pending');
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it('WebAuthn assertion passed through via attestationInputs', async () => {
    const savedFetch = globalThis.fetch;
    try {
      // Mock fetch — timestamp will succeed
      globalThis.fetch = mockTsaFetch() as unknown as typeof fetch;

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          deferrable: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      const webauthnAssertion = {
        signature: 'base64sig',
        credentialKeyId: 'cred-123',
        algorithm: 'ES256' as const,
      };

      const result = await tzun.capture({
        ...validInput,
        attestationInputs: { webauthnAssertion },
      });

      expect(result.stored).toBe(true);
      expect(result.envelope.nonRepudiation.webauthnAssertion).toEqual(webauthnAssertion);
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it('signerIdentity passed through via attestationInputs', async () => {
    const savedFetch = globalThis.fetch;
    try {
      globalThis.fetch = mockTsaFetch() as unknown as typeof fetch;

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          deferrable: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      const signerIdentity = {
        idpToken: 'jwt-token-abc',
        idpIssuer: 'https://accounts.google.com',
      };

      const result = await tzun.capture({
        ...validInput,
        attestationInputs: { signerIdentity },
      });

      expect(result.stored).toBe(true);
      expect(result.envelope.nonRepudiation.signerIdentity).toEqual(signerIdentity);
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it('multiple captures with attestation maintain chain linking', async () => {
    const savedFetch = globalThis.fetch;
    try {
      globalThis.fetch = mockTsaFetch() as unknown as typeof fetch;

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          deferrable: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      const result1 = await tzun.capture({
        ...validInput,
        reason: 'First decision',
      });
      const result2 = await tzun.capture({
        ...validInput,
        reason: 'Second decision',
      });
      const result3 = await tzun.capture({
        ...validInput,
        reason: 'Third decision',
      });

      // First envelope has no chain link
      expect(result1.envelope.integrity.chainLink).toBeNull();

      // Second and third envelopes have chain links
      expect(result2.envelope.integrity.chainLink).toBeDefined();
      expect(result2.envelope.integrity.chainLink).not.toBeNull();
      expect(result3.envelope.integrity.chainLink).toBeDefined();
      expect(result3.envelope.integrity.chainLink).not.toBeNull();

      // Chain links are different
      expect(result2.envelope.integrity.chainLink).not.toBe(
        result3.envelope.integrity.chainLink,
      );

      // Sequence numbers are monotonically increasing
      expect(result1.envelope.payload.sequenceNumber).toBe(1);
      expect(result2.envelope.payload.sequenceNumber).toBe(2);
      expect(result3.envelope.payload.sequenceNumber).toBe(3);
    } finally {
      globalThis.fetch = savedFetch;
    }
  });
});

describe('Attestation Integration: End-to-End', () => {
  const validInput: CaptureInput = {
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    aiOutput: { recommendation: 'approve', confidence: 0.95 },
    action: 'approved',
    reason: 'All criteria met',
  };

  let savedFetch: typeof globalThis.fetch;

  beforeEach(() => {
    savedFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = savedFetch;
    jest.restoreAllMocks();
  });

  it('complete attestation: timestamp + webauthn → partial status', async () => {
    globalThis.fetch = mockTsaFetch() as unknown as typeof fetch;

    const tzun = await Tzun.init({
      mode: 'dev',
      attestation: {
        require: ['timestamp'],
        timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
      },
    });

    const webauthnAssertion = {
      signature: 'base64-sig-e2e',
      credentialKeyId: 'cred-e2e-001',
      algorithm: 'ES256' as const,
      authenticatorData: 'base64-authdata',
      clientDataJSON: 'base64-clientdata',
    };

    const result = await tzun.capture({
      ...validInput,
      attestationInputs: { webauthnAssertion },
    });

    expect(result.stored).toBe(true);
    // timestamp present, no blockchain → partial
    expect(result.envelope.attestationStatus).toBe('partial');
    // both artifacts present in nonRepudiation
    expect(result.envelope.nonRepudiation.rfc3161Token).toBeDefined();
    expect(result.envelope.nonRepudiation.webauthnAssertion).toEqual(webauthnAssertion);
    // digest integrity holds
    const verification = await tzun.verify(result.envelope.payload.evidenceId);
    expect(verification.verified).toBe(true);
  });

  it('capture failure does not advance chain state', async () => {
    // Set up a mock that fails once, then succeeds — must be set before init()
    // so the RFC3161Client captures it at construction time.
    const mockFetch = jest.fn()
      .mockRejectedValueOnce(new Error('TSA unavailable'))
      .mockImplementation(mockTsaFetch());
    globalThis.fetch = mockFetch;

    const tzun = await Tzun.init({
      mode: 'dev',
      attestation: {
        require: ['timestamp'],
        timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
      },
    });

    const failure = await tzun.capture(validInput);
    expect(failure.stored).toBe(false);
    expect(failure.failure!.failureType).toBe('attestation_failure');

    // Second capture: TSA now succeeds
    const success = await tzun.capture(validInput);
    expect(success.stored).toBe(true);
    // The successful capture is the genesis — no prior stored envelope advanced the chain
    expect(success.envelope.integrity.chainLink).toBeNull();
    expect(success.envelope.payload.sequenceNumber).toBe(1);
  });

  it('a required timestamp that fails aborts the capture', async () => {
    globalThis.fetch = jest.fn().mockRejectedValue(new Error('TSA unavailable'));

    const tzun = await Tzun.init({
      mode: 'dev',
      attestation: {
        require: ['timestamp'],
        timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
      },
    });

    const result = await tzun.capture(validInput);

    expect(result.stored).toBe(false);
    expect(result.failure).toBeDefined();
    expect(result.failure!.failureType).toBe('attestation_failure');
    expect(result.failure!.diagnosticMetadata.missingServices).toContain('timestamp');
  });

  it('all attestation disabled in dev mode: status is none', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      // No attestation config at all
    });

    const result = await tzun.capture(validInput);

    expect(result.stored).toBe(true);
    expect(result.envelope.attestationStatus).toBe('none');
    expect(result.envelope.nonRepudiation).toEqual({});
  });

  it('signerIdentity from Google OAuth passed through alongside timestamp', async () => {
    globalThis.fetch = mockTsaFetch() as unknown as typeof fetch;

    const tzun = await Tzun.init({
      mode: 'dev',
      attestation: {
        require: ['timestamp'],
        timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
      },
    });

    const signerIdentity = {
      idpToken: 'google-jwt-token-xyz',
      idpIssuer: 'https://accounts.google.com',
    };

    const result = await tzun.capture({
      ...validInput,
      attestationInputs: { signerIdentity },
    });

    expect(result.stored).toBe(true);
    // timestamp present → at least partial
    expect(result.envelope.attestationStatus).toBe('partial');
    // rfc3161 timestamp present
    expect(result.envelope.nonRepudiation.rfc3161Token).toBeDefined();
    // signerIdentity passed through intact
    expect(result.envelope.nonRepudiation.signerIdentity).toEqual(signerIdentity);
  });
});

describe('Attestation Integration: failures are observable and recoverable', () => {
  const validInput = {
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    aiOutput: { recommendation: 'approve' },
    action: 'approved',
    reason: 'looks right',
  };

  it('reports the upstream error on the log sink instead of swallowing it', async () => {
    const savedFetch = globalThis.fetch;
    const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
    try {
      globalThis.fetch = jest
        .fn()
        .mockRejectedValue(new Error('getaddrinfo ENOTFOUND typo-tsa.example'));

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          deferrable: ['timestamp'],
          timestamp: { rfc3161Url: 'https://typo-tsa.example/tsr' },
        },
        onLog: (event, fields) => events.push({ event, fields }),
      });

      await tzun.capture(validInput);

      const failures = events.filter((e) => e.event === 'attestation_component_failed');
      expect(failures.length).toBeGreaterThan(0);
      expect(failures[0].fields.component).toBe('timestamp');
      // The whole point: a typo'd URL must be distinguishable from an outage.
      expect(String(failures[0].fields.error)).toContain('typo-tsa.example');
      await tzun.close();
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it('leaves the record where retryPendingAttestations() can find it', async () => {
    const savedFetch = globalThis.fetch;
    try {
      globalThis.fetch = jest.fn().mockRejectedValue(new Error('network error'));

      const tzun = await Tzun.init({
        mode: 'dev',
        attestation: {
          deferrable: ['timestamp'],
          timestamp: { rfc3161Url: 'https://mock-tsa.example/tsr' },
        },
      });

      const result = await tzun.capture(validInput);
      const storage = tzun.getStorage();

      // No hand-editing of the status: the capture itself must land in the
      // queue the retry loop reads.
      const queued = await storage.listByMissingObtainable(['timestamp']);
      expect(queued.map((e) => e.payload.evidenceId)).toContain(
        result.envelope.payload.evidenceId,
      );
      await tzun.close();
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it("still records 'none' when no attestation was configured at all", async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    const result = await tzun.capture(validInput);
    expect(result.envelope.attestationStatus).toBe('none');
    await tzun.close();
  });
});
