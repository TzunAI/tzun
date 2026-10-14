/**
 * The credential store outlives the process.
 *
 * WHY IT MATTERS. A credential store that lives only in process memory loses
 * every registered passkey on every redeploy. The evidence records those keys
 * signed stay in the chain; the keys that would let anyone check the
 * signatures do not, and `verify()` can only report `signatureValid: null` /
 * `no_credential_store` for every record ever captured. A signature nobody can
 * ever check is not evidence of a signature; it is a claim that one existed.
 *
 * This file pins the three things that make the store an evidence store rather
 * than a session cache:
 *   1. it survives the process (a new adapter on the same file sees it);
 *   2. it is append-only in the DATABASE, not just in the absence of a delete
 *      method;
 *   3. revocation is applied AS OF an instant, so a key revoked in June does
 *      not retroactively invalidate what it signed in March.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { AttestationArtifacts } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { credentialStoreFor } from '../../src/storage/credential-stores';
import { HttpStorageAdapter, HttpTransport } from '../../src/sdk/http-transport';
import {
  StoredCredential,
  credentialStatusAt,
} from '../../src/attestation/credential-store';
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import { makeGenuineAssertion, ORIGIN, RP_ID, sha256hex } from './attestation-assertion-helpers';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const CRED: StoredCredential = {
  credentialId: 'cred-jane-yubikey',
  publicKey: 'base64-public-key',
  userId: 'jane@acme.example',
  algorithm: 'ES256',
  counter: 0,
  status: 'active',
  registeredAt: '2026-03-22T10:00:00.000Z',
};

describe('a registered credential survives the process that registered it', () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-cred-durability-'));
    dbPath = join(dir, 'evidence.db');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('a redeploy — a brand-new adapter on the same file — still holds the key', async () => {
    const first = new SqliteStorageAdapter(dbPath);
    await first.credentialStore().register(CRED);
    await first.close();

    // The redeploy. Nothing of the first adapter survives except the file.
    const second = new SqliteStorageAdapter(dbPath);
    const found = await second.credentialStore().getByCredentialId(CRED.credentialId);
    await second.close();

    expect(found).toEqual(CRED);
  });

  it('the key lives in the same file as the evidence it signed', async () => {
    const adapter = new SqliteStorageAdapter(dbPath);
    await adapter.credentialStore().register(CRED);
    await adapter.close();

    // One file to back up, one file to restore, one file to hand to an
    // auditor. Keys kept anywhere else would have a different lifetime from
    // the evidence they verify.
    const raw = new Database(dbPath, { readonly: true });
    const rows = raw
      .prepare('SELECT credential_id, event_type FROM credential_events')
      .all() as Array<{ credential_id: string; event_type: string }>;
    raw.close();

    expect(rows).toEqual([{ credential_id: CRED.credentialId, event_type: 'registered' }]);
  });

  it('refuses a DELETE of a registration row at the sqlite3 prompt, not just through the API', async () => {
    const adapter = new SqliteStorageAdapter(dbPath);
    await adapter.credentialStore().register(CRED);
    await adapter.close();

    const raw = new Database(dbPath);
    expect(() => raw.prepare('DELETE FROM credential_events').run()).toThrow(
      'credential_events rows cannot be deleted'
    );
    // And a rewrite is refused too: a registration record whose public key can
    // be edited in place proves nothing about which key signed what.
    expect(() =>
      raw.prepare("UPDATE credential_events SET public_key = 'forged'").run()
    ).toThrow('credential_events is append-only');
    raw.close();
  });

  it('revocation keeps the row and records when it took effect', async () => {
    const adapter = new SqliteStorageAdapter(dbPath);
    const store = adapter.credentialStore();
    await store.register(CRED);
    await store.revoke(CRED.credentialId, {
      revokedAt: '2026-06-01T09:00:00.000Z',
      reason: 'offboarded',
    });
    const events = await store.history(CRED.credentialId);
    const cred = await store.getByCredentialId(CRED.credentialId);
    await adapter.close();

    expect(events.map((e) => e.type)).toEqual(['registered', 'revoked']);
    expect(cred?.revokedAt).toBe('2026-06-01T09:00:00.000Z');
    expect(cred?.publicKey).toBe(CRED.publicKey); // still verifiable
  });
});

describe('revocation is applied as of an instant, not retroactively', () => {
  const revoked: StoredCredential = {
    ...CRED,
    status: 'revoked',
    revokedAt: '2026-06-01T09:00:00.000Z',
  };

  it('a signature made before the revocation was made by a valid key', () => {
    // The March record is not forged because the key was revoked in June, any
    // more than a cancelled passport invalidates the visa stamps it collected
    // while it was valid. `StoredCredential.status` alone cannot say this —
    // it only ever reports the key's state NOW.
    expect(credentialStatusAt(revoked, '2026-03-23T00:00:00.000Z')).toBe('active');
  });

  it('a signature made after the revocation was not', () => {
    expect(credentialStatusAt(revoked, '2026-06-02T00:00:00.000Z')).toBe('revoked');
  });

  it('a signature made at the very instant of revocation is not', () => {
    expect(credentialStatusAt(revoked, '2026-06-01T09:00:00.000Z')).toBe('revoked');
  });

  it('a signature that predates its own key is the genuinely suspicious case', () => {
    expect(credentialStatusAt(revoked, '2026-01-01T00:00:00.000Z')).toBe('not_yet_registered');
  });

  it('falls back to the current status when an instant cannot be parsed', () => {
    // A verifier must answer, not throw, on input it did not produce.
    expect(credentialStatusAt(revoked, 'not-a-date')).toBe('revoked');
    expect(credentialStatusAt({ ...CRED, registeredAt: 'nonsense' }, '2026-06-02T00:00:00Z')).toBe(
      'active'
    );
  });
});

describe('verify() uses the durable store when there is one, and says so when there is not', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-cred-verify-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function artifactsSignedByAStoredKey(dbPath: string): Promise<{
    artifacts: AttestationArtifacts;
    challenge: string;
    adapter: SqliteStorageAdapter;
  }> {
    const challenge = sha256hex('the-record-digest');
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge,
      credentialId: CRED.credentialId,
    });
    const adapter = new SqliteStorageAdapter(dbPath);
    await adapter.credentialStore().register({ ...CRED, publicKey: publicKeyBase64 });
    return { artifacts: { webauthnAssertion: assertion }, challenge, adapter };
  }

  it('verifies a signature against a key read back off disk after a redeploy', async () => {
    const dbPath = join(dir, 'evidence.db');
    const { artifacts, challenge, adapter } = await artifactsSignedByAStoredKey(dbPath);
    await adapter.close();

    // The redeploy again: a new adapter, a new store, nothing in RAM.
    const reopened = new SqliteStorageAdapter(dbPath);
    const snapshot = await reopened.credentialStore().snapshot([CRED.credentialId]);
    const verdict = await verifyAttestation(artifacts, 'the-record-digest', snapshot, {
      expectedChallenge: challenge,
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });
    await reopened.close();

    expect(verdict.signatureValid).toBe(true);
    expect(verdict.signatureReason).toBeUndefined();
  });

  it('still reports no_credential_store when no store is supplied', async () => {
    const dbPath = join(dir, 'evidence.db');
    const { artifacts, adapter } = await artifactsSignedByAStoredKey(dbPath);
    await adapter.close();

    const verdict = await verifyAttestation(artifacts, 'the-record-digest', undefined);

    // "Cannot check" stays "cannot check". A persistent store must not turn an
    // unverifiable record into a verified one.
    expect(verdict.signatureValid).toBeNull();
    expect(verdict.signatureReason).toBe('no_credential_store');
  });
});

describe('credentialStoreFor — which adapters have a credential directory', () => {
  it('finds one on the local adapters', async () => {
    const mem = new MemoryStorageAdapter();
    expect(credentialStoreFor(mem)).toBeDefined();
    await mem.close();
  });

  it('returns undefined for the cloud transport, where the managed backend holds the keys', () => {
    const http = new HttpStorageAdapter(
      new HttpTransport({ apiKey: 'k', fetchFn: async () => new Response('{}') })
    );
    // undefined is a real answer and callers must keep handling it: it is what
    // keeps verify() reporting no_credential_store instead of inventing a
    // verdict it cannot support.
    expect(credentialStoreFor(http)).toBeUndefined();
  });

  it('hands the memory adapter the SAME directory on every call', async () => {
    // A fresh empty directory per call would make register() and
    // getByCredentialId() disagree — exactly the double-vs-real-store
    // divergence the conformance suites exist to catch.
    const mem = new MemoryStorageAdapter();
    await mem.credentialStore().register(CRED);
    expect(await mem.credentialStore().getByCredentialId(CRED.credentialId)).toEqual(CRED);
    await mem.close();
  });
});

// ── Postgres append-only enforcement (integration-gated) ──────────────────
//
// Runs when the Postgres legs do (tests/ts/helpers/postgres-test-db.ts), in a
// schema of this file's own.

const pgSchema = pgSuiteSchema('cred_durability');

(PG_TESTS_ENABLED ? describe : describe.skip)(
  'postgres refuses to rewrite or remove a registration record',
  () => {
    let adapter: import('../../src/storage/postgres').PostgresStorageAdapter;
    let credentialId: string;

    beforeAll(async () => {
      const { PostgresStorageAdapter } = await import('../../src/storage/postgres');
      adapter = new PostgresStorageAdapter(pgSchema.url);
      await adapter.ensureTables();
      credentialId = `cred-append-only-${Date.now()}`;
      await adapter.credentialStore().register({ ...CRED, credentialId });
    });

    afterAll(async () => {
      await adapter?.close();
    });

    const pool = () =>
      (adapter as unknown as { pool: import('pg').Pool }).pool;

    it('refuses UPDATE', async () => {
      await expect(
        pool().query("UPDATE credential_events SET public_key = 'forged' WHERE credential_id = $1", [
          credentialId,
        ])
      ).rejects.toThrow('append-only');
    });

    it('refuses DELETE', async () => {
      await expect(
        pool().query('DELETE FROM credential_events WHERE credential_id = $1', [credentialId])
      ).rejects.toThrow('append-only');
    });

    it('refuses TRUNCATE — a row trigger does not fire on one', async () => {
      // Row-level DELETE triggers are silent on TRUNCATE. Without a BEFORE
      // TRUNCATE ... FOR EACH STATEMENT trigger the entire credential
      // directory could be emptied in a single statement with every other
      // guard in this file looking on.
      await expect(pool().query('TRUNCATE credential_events')).rejects.toThrow('append-only');
    });
  }
);
