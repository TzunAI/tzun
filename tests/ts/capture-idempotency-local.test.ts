import type { EnvelopeInput } from '@tzun/engine';
/**
 * `capture()` under an idempotency key, on a local store.
 *
 * The adapters gained claim-or-replay first (`storeIdempotent`); this file pins
 * what `capture()` makes of it, which is the whole point of the key:
 *
 *   - the same key with the same input REPLAYS — nothing is stored, and the
 *     result is the record that exists, marked `replayed: true`;
 *   - the same key with different input is REFUSED as `idempotency_conflict`,
 *     not retryable, the local twin of the platform's 422;
 *   - two concurrent captures under one key leave one record;
 *   - a refused capture does not consume its key, so a later capture under it
 *     succeeds;
 *   - no key, or an adapter that cannot claim one, behaves exactly as before.
 *
 * Legs: memory and sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own,
 * emptied before each case.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { assembleEnvelope, SchemaRegistry } from '@tzun/engine';
import type { CaptureInput, TzunConfig } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

// A schema of this file's own, emptied before each Postgres case.
const pgSchema = pgSuiteSchema('capture_idem');

interface Leg {
  name: 'memory' | 'sqlite' | 'postgres';
  /** Storage config for Tzun.init(), on a store with nothing in it. */
  config: () => Promise<{ config: TzunConfig; teardown: () => Promise<void> }>;
  /** Can two Tzun instances share this store? (A memory adapter is per-instance.) */
  shareable: boolean;
}

const legs: Leg[] = [
  {
    name: 'memory',
    shareable: false,
    config: async () => ({ config: {}, teardown: async () => undefined }),
  },
  {
    name: 'sqlite',
    shareable: true,
    config: async () => {
      const dbPath = path.join(
        os.tmpdir(),
        `tzun-test-capture-idem-${process.pid}-${Math.random().toString(36).slice(2)}.db`,
      );
      return {
        config: { dbPath },
        teardown: async () => {
          for (const suffix of ['', '-wal', '-shm']) {
            try {
              fs.unlinkSync(dbPath + suffix);
            } catch {
              /* ignore */
            }
          }
        },
      };
    },
  },
];
if (PG_TESTS_ENABLED) {
  legs.push({
    name: 'postgres',
    shareable: true,
    config: async () => {
      await pgSchema.empty();
      return { config: { dbUrl: pgSchema.url }, teardown: async () => undefined };
    },
  });
}

const decision = (overrides: Partial<EnvelopeInput> = {}): EnvelopeInput => ({
  aiSystemId: 'underwriter-v2',
  aiOutput: { recommendation: 'approve', score: 0.92 },
  action: 'approved',
  reason: 'meets policy',
  decider: { kind: 'human' as const, id: 'acct:reviewer-bank.example', agent: null, credential: null, freshness: null },
  ...overrides,
});

describe.each(legs)('a keyed capture on a local store — $name', (leg) => {
  let tzun: Tzun;
  let extras: Tzun[] = [];
  let teardown: () => Promise<void>;
  let storageConfig: TzunConfig;

  async function init(extra: TzunConfig = {}): Promise<Tzun> {
    const made = await leg.config();
    teardown = made.teardown;
    storageConfig = made.config;
    tzun = await Tzun.init({ ...made.config, ...extra });
    return tzun;
  }

  /** A second SDK instance on the same store (sqlite / postgres only). */
  async function second(extra: TzunConfig = {}): Promise<Tzun> {
    const other = await Tzun.init({ ...storageConfig, ...extra });
    extras.push(other);
    return other;
  }

  afterEach(async () => {
    for (const extra of extras) await extra.close();
    extras = [];
    await tzun?.close();
    await teardown?.();
  });

  it('the same key with the same input replays the original record, and stores nothing', async () => {
    await init();
    const input = decision();

    const first = await tzun.capture(input, { idempotencyKey: 'order-8801' });
    expect(first.stored).toBe(true);
    expect(first.replayed).toBeUndefined();

    const retry = await tzun.capture(input, { idempotencyKey: 'order-8801' });
    expect(retry.stored).toBe(true);
    expect(retry.replayed).toBe(true);
    expect(retry.failure).toBeUndefined();

    // The record the caller gets back is the one that exists, read from the
    // store — not the envelope this attempt built.
    expect(retry.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
    expect(retry.envelope.payload.sequenceNumber).toBe(1);
    expect(retry.envelope.integrity.canonicalDigest).toBe(first.envelope.integrity.canonicalDigest);
    expect(retry.envelope).toEqual((await tzun.get(first.envelope.payload.evidenceId))!.envelope);

    expect(await tzun.getStorage().getChainLength()).toBe(1);
    expect(await tzun.list()).toHaveLength(1);
  });

  it('a replay still replays after the chain head moved and after the key holder was read back', async () => {
    await init();
    const input = decision();
    const first = await tzun.capture(input, { idempotencyKey: 'order-8802' });
    await tzun.capture(decision({ reason: 'a different decision' }));
    expect(await tzun.getStorage().getChainLength()).toBe(2);

    const retry = await tzun.capture(input, { idempotencyKey: 'order-8802' });
    expect(retry.replayed).toBe(true);
    expect(retry.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
    expect(await tzun.getStorage().getChainLength()).toBe(2);

    // The replay left a head the next capture can link from.
    const next = await tzun.capture(decision({ reason: 'after the replay' }));
    expect(next.stored).toBe(true);
    expect(next.envelope.payload.sequenceNumber).toBe(3);
  });

  it('the same key with changed input is refused as idempotency_conflict, and stores nothing', async () => {
    await init();
    const first = await tzun.capture(decision(), { idempotencyKey: 'order-8803' });
    expect(first.stored).toBe(true);

    const conflict = await tzun.capture(decision({ action: 'declined' }), {
      idempotencyKey: 'order-8803',
    });
    expect(conflict.stored).toBe(false);
    expect(conflict.failure?.failureType).toBe('idempotency_conflict');
    expect(conflict.failure?.diagnosticMetadata).toMatchObject({
      code: 'idempotency_conflict',
      retryable: false,
      idempotencyKey: 'order-8803',
      conflictReason: 'fingerprint_mismatch',
    });
    expect(await tzun.getStorage().getChainLength()).toBe(1);

    // The conflict did not disturb the key: the original input still replays.
    const retry = await tzun.capture(decision(), { idempotencyKey: 'order-8803' });
    expect(retry.replayed).toBe(true);
    expect(retry.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
    expect(await tzun.getStorage().getChainLength()).toBe(1);
  });

  it('what the SDK mints per attempt is not part of the input, so a retry is not a conflict', async () => {
    await init();
    const input = decision();
    const first = await tzun.capture(input, { idempotencyKey: 'order-8804' });
    // Two attempts of one decision differ in evidenceId and capturedAt; the
    // fingerprint covers neither, which is what makes the retry a replay.
    const retry = await tzun.capture(input, { idempotencyKey: 'order-8804' });
    expect(retry.replayed).toBe(true);
    expect(retry.envelope.payload.capturedAt).toBe(first.envelope.payload.capturedAt);
  });

  it('the same key with another signoff expectation is idempotency_conflict; the same expectation replays', async () => {
    await init();
    const expected = { policyDigest: 'a'.repeat(64) };
    const first = await tzun.capture(decision(), { idempotencyKey: 'order-8806', signoffExpectation: expected });
    expect(first.stored).toBe(true);

    for (const other of [{ policyDigest: 'b'.repeat(64) }, null]) {
      const conflict = await tzun.capture(decision(), { idempotencyKey: 'order-8806', signoffExpectation: other });
      expect(conflict.stored).toBe(false);
      expect(conflict.failure?.diagnosticMetadata).toMatchObject({
        code: 'idempotency_conflict',
        conflictReason: 'fingerprint_mismatch',
      });
    }

    const retry = await tzun.capture(decision(), { idempotencyKey: 'order-8806', signoffExpectation: { ...expected } });
    expect(retry.replayed).toBe(true);
    expect(retry.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
    expect(retry.envelope.payload.signoffExpectation).toEqual(expected);
    expect(await tzun.getStorage().getChainLength()).toBe(1);
  });

  it('two concurrent captures under one key produce one record', async () => {
    await init();
    const input = decision();
    const results = await Promise.all([
      tzun.capture(input, { idempotencyKey: 'order-8805' }),
      tzun.capture(input, { idempotencyKey: 'order-8805' }),
    ]);

    expect(results.map((r) => r.stored)).toEqual([true, true]);
    expect(results.filter((r) => r.replayed === true)).toHaveLength(1);
    const ids = new Set(results.map((r) => r.envelope.payload.evidenceId));
    expect(ids.size).toBe(1);
    expect(await tzun.getStorage().getChainLength()).toBe(1);
  });

  (leg.shareable ? it : it.skip)(
    'two SDK instances racing on one store under one key produce one record',
    async () => {
      await init();
      const other = await second();
      const input = decision();

      const results = await Promise.all([
        tzun.capture(input, { idempotencyKey: 'order-8806' }),
        other.capture(input, { idempotencyKey: 'order-8806' }),
      ]);

      expect(results.map((r) => r.stored)).toEqual([true, true]);
      expect(results.filter((r) => r.replayed === true)).toHaveLength(1);
      expect(new Set(results.map((r) => r.envelope.payload.evidenceId)).size).toBe(1);
      expect(await tzun.getStorage().getChainLength()).toBe(1);
    },
  );

  it('a refused capture leaves the key unclaimed, and a later capture under it succeeds', async () => {
    // One append attempt per capture, so the first refusal is final rather than
    // retried at the next position.
    await init({ chainConflictMaxAttempts: 1 });
    const first = await tzun.capture(decision({ reason: 'first' }));
    expect(first.stored).toBe(true);

    // Another writer appends behind this instance's back, so the head it holds
    // is stale and the store refuses the conditional append inside
    // storeIdempotent — which must roll the key claim back with it.
    const outOfBand = assembleEnvelope(decision({ reason: 'another writer' }), { previousDigest: first.envelope.integrity.canonicalDigest, sequenceNumber: 2 });
    await tzun.getStorage().store(outOfBand);

    const refused = await tzun.capture(decision({ reason: 'refused' }), {
      idempotencyKey: 'order-8807',
    });
    expect(refused.stored).toBe(false);
    expect(refused.failure?.failureType).toBe('chain_conflict');
    expect(await tzun.getStorage().getChainLength()).toBe(2);

    // The key was never consumed, so the same key captures now.
    const after = await tzun.capture(decision({ reason: 'after the refusal' }), {
      idempotencyKey: 'order-8807',
    });
    expect(after.stored).toBe(true);
    expect(after.replayed).toBeUndefined();
    expect(after.envelope.payload.sequenceNumber).toBe(3);
    expect(await tzun.getStorage().getChainLength()).toBe(3);
  });

  it('no key stores every capture, as before', async () => {
    await init();
    const input = decision();
    const first = await tzun.capture(input);
    const again = await tzun.capture(input);

    expect([first, again].every((r) => r.stored && r.replayed === undefined)).toBe(true);
    expect(first.envelope.payload.evidenceId).not.toBe(again.envelope.payload.evidenceId);
    expect(await tzun.getStorage().getChainLength()).toBe(2);
  });

  it('an adapter that cannot claim a key stores unconditionally, as before', async () => {
    await init();
    // A custom StorageAdapter without the optional method: the key goes into
    // StoreOptions for a transport that can use it, and store() writes.
    (tzun.getStorage() as { storeIdempotent?: unknown }).storeIdempotent = undefined;

    const input = decision();
    const first = await tzun.capture(input, { idempotencyKey: 'order-8808' });
    const retry = await tzun.capture(input, { idempotencyKey: 'order-8808' });

    expect([first, retry].every((r) => r.stored && r.replayed === undefined)).toBe(true);
    expect(await tzun.getStorage().getChainLength()).toBe(2);
  });
});
