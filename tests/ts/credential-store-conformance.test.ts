/**
 * Credential-store conformance — one contract, every backend.
 *
 * The credential store has three backends, and one contract asks all three
 * the same questions, so a store cannot behave one way in development and
 * another in production without a case here failing.
 *
 * Legs:
 *   - memory   — always (`MemoryCredentialStore`, the double).
 *   - sqlite   — always; a fresh temp file per case.
 *   - postgres — when the Postgres legs run
 *                (tests/ts/helpers/postgres-test-db.ts), in a schema of this
 *                file's own. The append-only triggers refuse TRUNCATE, which
 *                is the point, so every case generates unique credential ids
 *                and asserts against its own user id.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import {
  AsyncCredentialStore,
  CredentialAlreadyRegisteredError,
  InvalidCredentialInstantError,
  CredentialNotFoundError,
  CredentialSnapshotReadOnlyError,
  StoredCredential,
} from '../../src/attestation/credential-store';

interface Leg {
  store: AsyncCredentialStore;
  teardown: () => Promise<void>;
}

function credential(overrides: Partial<StoredCredential> = {}): StoredCredential {
  const id = `cred-${randomUUID()}`;
  return {
    credentialId: id,
    publicKey: `pk-${id}`,
    userId: `user-${randomUUID()}@acme.test`,
    algorithm: 'ES256',
    counter: 0,
    status: 'active',
    registeredAt: '2026-03-22T10:00:00.000Z',
    ...overrides,
  };
}

function describeCredentialConformance(name: string, open: () => Promise<Leg>): void {
  describe(`credential store conformance — ${name}`, () => {
    let leg: Leg;
    let store: AsyncCredentialStore;

    beforeEach(async () => {
      leg = await open();
      store = leg.store;
    });

    afterEach(async () => {
      await leg.teardown();
    });

    it('registers a credential and reads it back by id', async () => {
      const cred = credential();
      await store.register(cred);
      expect(await store.getByCredentialId(cred.credentialId)).toEqual(cred);
    });

    it('returns undefined for a credential id that was never registered', async () => {
      expect(await store.getByCredentialId(`cred-${randomUUID()}`)).toBeUndefined();
    });

    it('reads every credential registered to a user, in registration order', async () => {
      const userId = `user-${randomUUID()}@acme.test`;
      const first = credential({ userId, registeredAt: '2026-03-22T10:00:00.000Z' });
      const second = credential({ userId, registeredAt: '2026-03-22T11:00:00.000Z' });
      await store.register(first);
      await store.register(second);
      expect((await store.getByUserId(userId)).map((c) => c.credentialId)).toEqual([
        first.credentialId,
        second.credentialId,
      ]);
    });

    it('refuses a second registration of the same credential id', async () => {
      const cred = credential();
      await store.register(cred);
      await expect(store.register(cred)).rejects.toThrow(CredentialAlreadyRegisteredError);
      await expect(store.register(cred)).rejects.toThrow('already registered');
    });

    it('refuses to revoke a credential that is not there', async () => {
      await expect(store.revoke(`cred-${randomUUID()}`)).rejects.toThrow(CredentialNotFoundError);
      await expect(store.revoke(`cred-${randomUUID()}`)).rejects.toThrow('not found');
    });

    it('records the revocation instant, not just the status', async () => {
      const cred = credential();
      await store.register(cred);
      await store.revoke(cred.credentialId, {
        revokedAt: '2026-06-01T09:00:00.000Z',
        reason: 'laptop lost',
      });
      const after = await store.getByCredentialId(cred.credentialId);
      expect(after?.status).toBe('revoked');
      // Without the instant, revocation can only be applied retroactively to
      // every signature the key ever produced.
      expect(after?.revokedAt).toBe('2026-06-01T09:00:00.000Z');
      expect(after?.revocationReason).toBe('laptop lost');
    });

    it('keeps a revoked credential readable — revocation is not deletion', async () => {
      const cred = credential();
      await store.register(cred);
      await store.revoke(cred.credentialId);
      const after = await store.getByCredentialId(cred.credentialId);
      expect(after).toBeDefined();
      expect(after?.publicKey).toBe(cred.publicKey);
    });

    it('lets the first revocation stand — a later one does not move the date', async () => {
      const cred = credential();
      await store.register(cred);
      await store.revoke(cred.credentialId, { revokedAt: '2026-06-01T09:00:00.000Z' });
      await store.revoke(cred.credentialId, { revokedAt: '2026-01-01T00:00:00.000Z' });
      expect((await store.getByCredentialId(cred.credentialId))?.revokedAt).toBe(
        '2026-06-01T09:00:00.000Z'
      );
    });

    it('raises the signature counter', async () => {
      const cred = credential();
      await store.register(cred);
      await store.updateCounter(cred.credentialId, 5);
      expect((await store.getByCredentialId(cred.credentialId))?.counter).toBe(5);
    });

    it('refuses to update the counter of a credential that is not there', async () => {
      await expect(store.updateCounter(`cred-${randomUUID()}`, 1)).rejects.toThrow(
        CredentialNotFoundError
      );
    });

    it('keeps the high-water mark and records a counter that goes backwards', async () => {
      // A counter that does not increase is the WebAuthn authenticator-cloning
      // signal. Assigning the lower value would mean the next genuine
      // assertion looks like an increase and the signal is gone before anyone
      // can look for it.
      const cred = credential();
      await store.register(cred);
      await store.updateCounter(cred.credentialId, 9);
      await store.updateCounter(cred.credentialId, 3);
      const after = await store.getByCredentialId(cred.credentialId);
      expect(after?.counter).toBe(9);
      expect(after?.counterRegressedAt).toBeDefined();
    });

    it('records registration and revocation as events, oldest first', async () => {
      const cred = credential();
      await store.register(cred);
      await store.revoke(cred.credentialId, { revokedAt: '2026-06-01T09:00:00.000Z' });
      const events = await store.history(cred.credentialId);
      expect(events.map((e) => e.type)).toEqual(['registered', 'revoked']);
      expect(events[0].occurredAt).toBe(cred.registeredAt);
      expect(events[0].publicKey).toBe(cred.publicKey);
      expect(events[1].occurredAt).toBe('2026-06-01T09:00:00.000Z');
      // recordedAt is when the store heard about it, occurredAt is when it
      // happened; both are kept because the gap is itself auditable.
      expect(events[1].recordedAt).toEqual(expect.any(String));
    });

    it('refuses an instant no backend could store — the same refusal everywhere', async () => {
      // Postgres would reject it anyway (occurred_at is TIMESTAMPTZ) while the
      // memory and SQLite backends would store the string happily, so without
      // this guard a store that works in dev would throw in production on the
      // same input.
      await expect(store.register(credential({ registeredAt: 'last Tuesday' }))).rejects.toThrow(
        InvalidCredentialInstantError
      );
      const cred = credential();
      await store.register(cred);
      await expect(
        store.revoke(cred.credentialId, { revokedAt: 'whenever' })
      ).rejects.toThrow(InvalidCredentialInstantError);
      // and the refusal left nothing behind
      expect((await store.getByCredentialId(cred.credentialId))?.status).toBe('active');
    });

    it('hands a verification pass a read-only snapshot', async () => {
      const cred = credential();
      await store.register(cred);
      const snap = await store.snapshot([cred.credentialId]);
      expect(snap.getByCredentialId(cred.credentialId)?.publicKey).toBe(cred.publicKey);
      expect(() => snap.register(credential())).toThrow(CredentialSnapshotReadOnlyError);
      expect(() => snap.revoke(cred.credentialId)).toThrow(CredentialSnapshotReadOnlyError);
      expect(() => snap.updateCounter(cred.credentialId, 4)).toThrow(
        CredentialSnapshotReadOnlyError
      );
    });

    it('freezes the snapshot: a revocation after it is taken does not change it', async () => {
      // A scan of 10,000 records that re-reads the directory per record can
      // report two different verdicts for two records signed by the same key,
      // because somebody revoked it halfway through the scan.
      const cred = credential();
      await store.register(cred);
      const snap = await store.snapshot([cred.credentialId]);
      await store.revoke(cred.credentialId);
      expect(snap.getByCredentialId(cred.credentialId)?.status).toBe('active');
      expect((await store.getByCredentialId(cred.credentialId))?.status).toBe('revoked');
    });
  });
}

// ── memory ────────────────────────────────────────────────────────────────

describeCredentialConformance('memory', async () => {
  const adapter = new MemoryStorageAdapter();
  return { store: adapter.credentialStore(), teardown: async () => adapter.close() };
});

// ── sqlite (temp file) ────────────────────────────────────────────────────

describeCredentialConformance('sqlite', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tzun-test-cred-conformance-'));
  const adapter = new SqliteStorageAdapter(join(dir, 'credentials.db'));
  return {
    store: adapter.credentialStore(),
    teardown: async () => {
      await adapter.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
});

// ── postgres (integration-gated) ──────────────────────────────────────────

const pgSchema = pgSuiteSchema('cred_conformance');

if (PG_TESTS_ENABLED) {
  describeCredentialConformance('postgres', async () => {
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    return { store: adapter.credentialStore(), teardown: async () => adapter.close() };
  });
} else {
  describe.skip('credential store conformance — postgres (set RUN_INTEGRATION_TESTS=true and DATABASE_URL)', () => {
    it('skipped', () => undefined);
  });
}
