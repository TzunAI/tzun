/**
 * The local half: a local store's refusals surface under stable failure types,
 * the way their cloud counterparts do.
 *
 * A duplicate evidence id (`DuplicateRecordError`) and an append to a sealed
 * chain (`assertChainNotSealed`) each get a failure type of their own, with a
 * `code` and `retryable`, rather than falling through `buildCaptureFailure` to
 * `serialization_failure`, which is the answer for a payload the canonicalizer
 * could not serialise. A caller deciding whether to re-send has to be able to
 * tell the three apart.
 *
 *   local failureType       cloud counterpart
 *   evidence_id_conflict    cloud_evidence_id_conflict (409, not retryable)
 *   chain_sealed            the platform's ChainSealedError, code `chain_sealed`
 *
 * Both carry `code` and `retryable: false` in `diagnosticMetadata`. Neither is
 * worth re-sending as is: the id is taken, and the chain is closed for good.
 */
import { Tzun } from '../../src/sdk/index';
import type { CaptureInput } from '@tzun/engine';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

// The module object itself, which the SDK's compiled `require('crypto')` reads
// `randomUUID` from; an ES namespace import is a frozen copy spyOn cannot patch.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const nodeCrypto: typeof import('crypto') = require('crypto');

const decision: CaptureInput = {
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Meets all criteria',
};

function storeCases(
  label: string,
  makeTzun: () => Promise<Tzun>,
  { sealing = true }: { sealing?: boolean } = {},
) {
  describe(label, () => {
    let tzun: Tzun;

    beforeEach(async () => {
      tzun = await makeTzun();
    });

    afterEach(async () => {
      jest.restoreAllMocks();
      await tzun.close();
    });

    it('a duplicate evidence id is evidence_id_conflict, not serialization_failure', async () => {
      const fixedId = nodeCrypto.randomUUID();
      jest.spyOn(nodeCrypto, 'randomUUID').mockReturnValue(fixedId);

      const first = await tzun.capture(decision);
      expect(first.stored).toBe(true);
      expect(first.envelope.payload.evidenceId).toBe(fixedId);

      const second = await tzun.capture(decision);
      expect(second.stored).toBe(false);
      expect(second.failure?.failureType).toBe('evidence_id_conflict');
      expect(second.failure?.evidenceId).toBe(fixedId);
      expect(second.failure?.diagnosticMetadata).toMatchObject({
        code: 'evidence_id_conflict',
        retryable: false,
      });

      // The record that holds the id is untouched.
      const held = await tzun.getStorage().retrieve(fixedId);
      expect(held!.integrity.canonicalDigest).toBe(first.envelope.integrity.canonicalDigest);
    });

    (sealing ? it : it.skip)('an append to a sealed chain is chain_sealed, not serialization_failure', async () => {
      const storage = tzun.getStorage();
      const sealedAt = new Date().toISOString();
      await storage.storeChain({ chainId: 'default', status: 'active', createdAt: sealedAt });
      await storage.sealChain('default', sealedAt);

      const result = await tzun.capture(decision);
      expect(result.stored).toBe(false);
      expect(result.failure?.failureType).toBe('chain_sealed');
      expect(result.failure?.diagnosticMetadata).toMatchObject({
        code: 'chain_sealed',
        retryable: false,
        chainId: 'default',
      });
      expect(await storage.getChainLength('default')).toBe(0);
    });

    it('any other store failure is still serialization_failure', async () => {
      jest.spyOn(tzun.getStorage(), 'store').mockRejectedValue(new Error('disk full'));
      const result = await tzun.capture(decision);
      expect(result.stored).toBe(false);
      expect(result.failure?.failureType).toBe('serialization_failure');
      expect(result.failure?.diagnosticMetadata.reason).toBe('disk full');
    });
  });
}

describe('local store refusals carry stable failure types', () => {
  storeCases('memory store', () => Tzun.init({ mode: 'dev' }));
  storeCases('SQLite store', () => Tzun.init({ mode: 'dev', dbPath: ':memory:' }));

  // A seal cannot be lifted on Postgres (the `chains` triggers refuse it), so
  // every case starts from this file's schema emptied, the seal with it.
  const pgSchema = pgSuiteSchema('refusal_failure_types');
  if (PG_TESTS_ENABLED) {
    storeCases('Postgres store', async () => {
      await pgSchema.empty();
      return Tzun.init({ mode: 'dev', dbUrl: pgSchema.url });
    });
  }

  describe('capture() with no input object', () => {
    let tzun: Tzun;

    beforeEach(async () => {
      tzun = await Tzun.init({ mode: 'dev' });
    });

    afterEach(async () => {
      await tzun.close();
    });

    it.each([
      ['undefined', undefined],
      ['null', null],
      ['a string', 'approve'],
      ['an array', [decision]],
    ])('capture(%s) returns a validation_failure instead of throwing', async (_label, input) => {
      const result = await tzun.capture(input as unknown as CaptureInput);
      expect(result.stored).toBe(false);
      expect(result.failure?.failureType).toBe('validation_failure');
      expect(result.failure?.diagnosticMetadata.field).toBe('input');
    });
  });
});
