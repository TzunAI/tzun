import { Tzun } from '../../src/sdk/index';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { EvidenceEnvelope } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';

describe('Tzun SDK', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init(); // defaults to dev mode, in-memory storage
  });

  describe('init', () => {
    it('creates an instance in dev mode by default', () => {
      expect(tzun).toBeDefined();
      expect(tzun.getMode()).toBe('dev');
    });

    it('creates an instance in local mode when configured', async () => {
      // init() only — no capture() here on purpose. `local` obtains an RFC
      // 3161 timestamp for every record, so a capture would be a live call to
      // freetsa.org, which the suite-wide guard refuses.
      const local = await Tzun.init({ mode: 'local', dbPath: ':memory:' });
      expect(local.getMode()).toBe('local');
    });

    it('uses provided schema version', async () => {
      const t = await Tzun.init({ schemaVersion: 'v1.0' });
      expect(t).toBeDefined();
    });
  });

  describe('capture', () => {
    it('captures an evidence record and returns envelope', async () => {
      const result = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'approve', confidence: 0.94 },
        action: 'approved',
        reason: 'All criteria met',
      });
      expect(result.stored).toBe(true);
      expect(result.envelope.envelopeVersion).toBe('e1');
      expect(result.envelope.payload.action).toBe('approved');
      expect(result.envelope.integrity.canonicalDigest).toMatch(/^[a-f0-9]{64}$/);
    });

    it('uses provided aiSystemId', async () => {
      const t = await Tzun.init({ aiSystemId: 'my-ai' });
      const result = await t.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { text: 'hello' },
        action: 'acknowledged',
        reason: 'Received',
      });
      expect(result.envelope.payload.aiSystemId).toBe('my-ai');
    });

    it('allows per-capture aiSystemId override', async () => {
      const result = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'override-ai',
        aiOutput: { text: 'hello' },
        action: 'acknowledged',
        reason: 'Received',
      });
      expect(result.envelope.payload.aiSystemId).toBe('override-ai');
    });

    it('verifies a NON-GENESIS record without the caller supplying previousDigest', async () => {
      // verify() resolves the predecessor's digest itself. Left undefined, a
      // non-genesis record's non-null chainLink would have nothing to check
      // against and score chainLinkValid=false -> verified=false. The REST route
      // maps that to a `chain_break` monitoring event, so a healthy chain would
      // raise a tamper incident and fire notifications on essentially every
      // on-demand verify.
      const first = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { text: 'one' }, action: 'accepted', reason: 'first',
      });
      const second = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { text: 'two' }, action: 'accepted', reason: 'second',
      });
      expect(second.envelope.payload.sequenceNumber).toBe(2);
      expect(second.envelope.integrity.chainLink).not.toBeNull();

      // No previousDigest argument — exactly how the REST route calls it.
      const result = await tzun.verify(second.envelope.payload.evidenceId);

      expect(result.chainLinkValid).toBe(true);
      expect(result.verified).toBe(true);

      // The genesis record still verifies, with nothing to check against.
      const genesis = await tzun.verify(first.envelope.payload.evidenceId);
      expect(genesis.chainLinkValid).toBeNull();
      expect(genesis.verified).toBe(true);
    });

    it('still detects a genuinely broken chain link with no previousDigest supplied', async () => {
      // The verifier must not be a rubber stamp: resolving the real
      // predecessor has to make a tampered link fail, not pass.
      await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { text: 'one' }, action: 'accepted', reason: 'first' });
      const second = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { text: 'two' }, action: 'accepted', reason: 'second',
      });

      // Rewrite the stored row; retrieve() returns a detached copy.
      await rewriteStoredEnvelope(tzun.getStorage(), second.envelope.payload.evidenceId, (e) => { e.integrity.chainLink = 'a'.repeat(64); });

      const result = await tzun.verify(second.envelope.payload.evidenceId);
      expect(result.chainLinkValid).toBe(false);
      expect(result.verified).toBe(false);
    });

    it('stores envelope retrievable via verify', async () => {
      const { envelope } = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { text: 'test' },
        action: 'accepted',
        reason: 'Valid',
      });
      const verifyResult = await tzun.verify(envelope.payload.evidenceId);
      expect(verifyResult.verified).toBe(true);
    });

    it('chains evidence records via chainLink', async () => {
      const r1 = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { step: 1 },
        action: 'approved',
        reason: 'First',
      });
      expect(r1.envelope.integrity.chainLink).toBeNull(); // first record

      const r2 = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { step: 2 },
        action: 'approved',
        reason: 'Second',
      });
      expect(r2.envelope.integrity.chainLink).not.toBeNull(); // chained
      expect(r2.envelope.integrity.chainLink).toMatch(/^[a-f0-9]{64}$/);
    });

    it('sets attestationStatus to none in dev mode', async () => {
      const result = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { text: 'test' },
        action: 'accepted',
        reason: 'Valid',
      });
      expect(result.envelope.attestationStatus).toBe('none');
    });

    it('returns failure result when capture input is invalid', async () => {
      const result = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: {} as Record<string, unknown>,
        action: '',
        reason: '',
      });
      expect(result.stored).toBe(false);
      expect(result.failure).toBeDefined();
      expect(result.failure!.failureType).toBe('validation_failure');
    });
  });

  describe('verify', () => {
    it('returns verified: true for a valid stored envelope', async () => {
      const { envelope } = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { text: 'test' },
        action: 'approved',
        reason: 'Good',
      });
      const result = await tzun.verify(envelope.payload.evidenceId);
      expect(result.verified).toBe(true);
      expect(result.storedDigest).toBe(envelope.integrity.canonicalDigest);
    });

    it('throws for non-existent evidenceId', async () => {
      await expect(tzun.verify('non-existent')).rejects.toThrow('not found');
    });
  });

  describe('storage resolution precedence', () => {
    it('explicit dbPath takes precedence over DATABASE_URL env var', async () => {
      const originalEnv = process.env.DATABASE_URL;
      try {
        process.env.DATABASE_URL = 'postgres://localhost:5432/fake';
        const t = await Tzun.init({ dbPath: ':memory:' });
        expect(t.getStorage()).toBeInstanceOf(SqliteStorageAdapter);
      } finally {
        if (originalEnv === undefined) {
          delete process.env.DATABASE_URL;
        } else {
          process.env.DATABASE_URL = originalEnv;
        }
      }
    });
  });
});
