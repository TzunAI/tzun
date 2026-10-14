/**
 * Two schedulers, one pending record: the second token never replaces the
 * first.
 *
 * `retryPendingAttestations()` runs on a timer, and a self-hosted deployment
 * can have several replicas on one store. Both passes see the same pending
 * record, both ask a TSA, and both come back with a token. An update that
 * spread the caller's artifacts over the stored ones would let whoever
 * committed second replace a timestamp that had already landed — a second
 * token over evidence that was already attested, and a second
 * `attestation_retry` revision row saying the record was written again.
 *
 * The adapters fill only what is absent, under the lock they already take, so
 * exactly one of the two tokens lands, the other is dropped, and the loser
 * writes nothing at all.
 *
 * Legs: sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { AttestationArtifacts, StorageAdapter } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { makeEnvelope } from './storage-conformance/fixtures';

interface Leg {
  name: 'sqlite' | 'postgres';
  make: () => Promise<{ adapter: StorageAdapter; teardown: () => Promise<void> }>;
}

const sqliteLeg: Leg = {
  name: 'sqlite',
  make: async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-'));
    const adapter = new SqliteStorageAdapter(path.join(dir, 'attest.db'));
    return {
      adapter,
      teardown: async () => {
        await adapter.close();
        fs.rmSync(dir, { recursive: true, force: true });
      },
    };
  },
};

const pgSchema = pgSuiteSchema('attestation_fill_only');

const postgresLeg: Leg = {
  name: 'postgres',
  make: async () => {
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    return { adapter, teardown: async () => adapter.close() };
  },
};

const legs: Leg[] = PG_TESTS_ENABLED ? [sqliteLeg, postgresLeg] : [sqliteLeg];

let counter = 0;
const unique = (label: string): string =>
  `${label}-${Date.now().toString(36)}-${(counter += 1)}-${Math.random().toString(36).slice(2, 8)}`;

describe.each(legs)('a concurrent attestation update never replaces what landed — $name', (leg) => {
  let adapter: StorageAdapter;
  let teardown: () => Promise<void>;

  beforeEach(async () => {
    ({ adapter, teardown } = await leg.make());
  });

  afterEach(async () => {
    await teardown();
  });

  it('two passes racing one record leave one token and one revision row', async () => {
    const evidenceId = unique('ev');
    const env = makeEnvelope({ evidenceId, attestationStatus: 'pending' });
    env.nonRepudiation = {};
    await adapter.store(env, unique('chain'));

    const token = (n: string): AttestationArtifacts => ({ rfc3161Token: `token-${n}` } as AttestationArtifacts);
    await Promise.all([
      adapter.updateAttestation(evidenceId, token('a'), 'complete'),
      adapter.updateAttestation(evidenceId, token('b'), 'complete'),
    ]);

    const stored = (await adapter.retrieve(evidenceId))!;
    expect(['token-a', 'token-b']).toContain(stored.nonRepudiation.rfc3161Token);
    expect(stored.attestationStatus).toBe('complete');

    // The loser filled nothing, so it wrote nothing: one attestation_retry row.
    const revisions = await adapter.listEnvelopeRevisions!(evidenceId);
    expect(revisions.filter((r) => r.cause === 'attestation_retry')).toHaveLength(1);
    expect(revisions.map((r) => r.canonicalDigest)).toEqual(
      revisions.map(() => env.integrity.canonicalDigest),
    );
  });

  it('a pass that arrives with a different component adds it without touching the first', async () => {
    const evidenceId = unique('ev');
    const env = makeEnvelope({ evidenceId, attestationStatus: 'pending' });
    env.nonRepudiation = {};
    await adapter.store(env, unique('chain'));

    await Promise.all([
      adapter.updateAttestation(evidenceId, { rfc3161Token: 'the-timestamp' } as AttestationArtifacts, 'partial'),
      adapter.updateAttestation(
        evidenceId,
        { anchor: { txHash: '0xabc', chain: 'sepolia' } } as unknown as AttestationArtifacts,
        'partial',
      ),
    ]);

    const stored = (await adapter.retrieve(evidenceId))!;
    expect(stored.nonRepudiation.rfc3161Token).toBe('the-timestamp');
    expect(stored.nonRepudiation.anchor).toMatchObject({ txHash: '0xabc' });
  });
});
