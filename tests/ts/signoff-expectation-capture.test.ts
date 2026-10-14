/**
 * The signature expectation (Record §9; Verification §5): every capture writes
 * `payload.signoffExpectation` into the record's hashed payload, `null` by
 * default; a capture refuses a value of the wrong shape; `verify()` reports a record that does not carry
 * the signature it expects; and a store a release before 0.7.0 wrote is
 * refused at open, with a typed error, rather than read as tampered.
 */
import { FIELD_SET_0_7, FIELD_SET_BEFORE_0_7 } from '@tzun/engine';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { Client, Pool } from 'pg';
import {
  assembleEnvelope,
  canonicalSerialize,
  computeDigest,
  SchemaRegistry,
  webauthnChallengeForDigest,
  type EvidenceEnvelope,
  type FailureRecord,
} from '@tzun/engine';
import {
  StoreSchemaOutdatedError,
  Tzun,
  type CaptureOptions,
  type PreparedAssertionChallenge,
} from '../../src/sdk/index';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { refuseOutdatedStore } from '../../src/sdk/store-schema-guard';
import { postgresSchemaSnapshot, sqliteSchemaSnapshot, stripLogSchemaPostgres, stripLogSchemaSqlite } from './helpers/store-schema';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const HEX = 'c'.repeat(64);
const decision = { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { recommendation: 'approve' }, action: 'approved', reason: 'Meets criteria' };
const HASHED = new SchemaRegistry().get('v1.0')!.hashedFieldSet;

/** A record from an earlier release, altered after its digest was taken: it recomputes under no set. */
function altered06(env: EvidenceEnvelope): EvidenceEnvelope {
  (env.payload as unknown as Record<string, unknown>).humanReason = 'rewritten';
  return env;
}

/**
 * A record exactly as an earlier release stored it: 0.6.x (the eight-name
 * set, no signoffExpectation key) by default, or 0.7.x (`'0.7'`: the nine
 * names, signoffExpectation null).
 */
function recordFrom06(sequenceNumber = 1, previousDigest?: string, generation: '0.7' | 'before-0.7' = 'before-0.7'): EvidenceEnvelope {
  const env = assembleEnvelope(decision, { previousDigest: previousDigest, sequenceNumber: sequenceNumber });
  const p = env.payload;
  const legacy: Record<string, unknown> = {
    evidenceId: p.evidenceId,
    schemaVersion: p.schemaVersion,
    aiSystemId: p.aiSystemId,
    aiOutput: p.aiOutput,
    humanAction: p.action,
    humanReason: p.reason,
    capturedAt: p.capturedAt,
    sequenceNumber: p.sequenceNumber,
    aiBom: null,
    ...(generation === '0.7' && { signoffExpectation: null }),
  };
  env.payload = legacy as unknown as EvidenceEnvelope['payload'];
  env.integrity.canonicalDigest = computeDigest(
    canonicalSerialize(legacy, [...(generation === '0.7' ? FIELD_SET_0_7 : FIELD_SET_BEFORE_0_7)]),
  );
  return env;
}

describe('capture writes signoffExpectation into the hashed payload', () => {
  let tzun: Tzun;
  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev' });
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('null by default, stored as a key, and the record verifies with nothing owed', async () => {
    const result = await tzun.capture(decision);
    expect(result.stored).toBe(true);
    expect(result.envelope.payload.signoffExpectation).toBeNull();
    const stored = await tzun.getStorage().retrieve(result.envelope.payload.evidenceId);
    expect(Object.prototype.hasOwnProperty.call(stored!.payload, 'signoffExpectation')).toBe(true);
    const verdict = await tzun.verify(result.envelope.payload.evidenceId);
    expect(verdict.verified).toBe(true);
    expect(verdict.signoffExpectationValid).toBe(true);
  });

  it('{ policyDigest }: stored, hashed, and reported as owed until a signature arrives', async () => {
    const result = await tzun.capture(decision, { signoffExpectation: { policyDigest: HEX } });
    expect(result.stored).toBe(true);
    expect(result.envelope.payload.signoffExpectation).toEqual({ policyDigest: HEX });
    const recomputed = computeDigest(
      canonicalSerialize(result.envelope.payload as unknown as Record<string, unknown>, HASHED),
    );
    expect(recomputed).toBe(result.envelope.integrity.canonicalDigest);

    const verdict = await tzun.verify(result.envelope.payload.evidenceId);
    expect(verdict.verified).toBe(true);
    expect(verdict.signoffExpectationValid).toBeNull();
    expect(verdict.signoffExpectationReason).toBe('signature_missing');
  });

  it('the caller\'s object is copied: changing it afterwards does not reach the record', async () => {
    const expectation = { policyDigest: HEX };
    const result = await tzun.capture(decision, { signoffExpectation: expectation });
    expectation.policyDigest = 'd'.repeat(64);
    const stored = await tzun.getStorage().retrieve(result.envelope.payload.evidenceId);
    expect(stored!.payload.signoffExpectation).toEqual({ policyDigest: HEX });
  });

  // The value the check judges is the value hashed: capture copies the
  // caller's object before its first await, so a change made while the
  // capture runs cannot put a value the check never saw into the record.
  it('a change to the caller\'s object while the capture runs does not reach the record', async () => {
    const expectation = { policyDigest: HEX };
    const pending = tzun.capture(decision, { signoffExpectation: expectation });
    expectation.policyDigest = 'NOT-HEX';
    const result = await pending;
    expect(result.stored).toBe(true);
    expect(result.envelope.payload.signoffExpectation).toEqual({ policyDigest: HEX });
    const verdict = await tzun.verify(result.envelope.payload.evidenceId);
    expect(verdict.signoffExpectationReason).toBe('signature_missing');
  });

  it('one options object reused across concurrent captures: each stores the value it was called with', async () => {
    const options: CaptureOptions = { signoffExpectation: { policyDigest: 'a'.repeat(64) } };
    const first = tzun.capture(decision, options);
    options.signoffExpectation = { policyDigest: 'b'.repeat(64) };
    const second = tzun.capture(decision, options);
    const [a, b] = await Promise.all([first, second]);
    expect(a.envelope.payload.signoffExpectation).toEqual({ policyDigest: 'a'.repeat(64) });
    expect(b.envelope.payload.signoffExpectation).toEqual({ policyDigest: 'b'.repeat(64) });
  });

  it('a getter is read once: the value the check judged is the value hashed', async () => {
    let reads = 0;
    const expectation = {};
    Object.defineProperty(expectation, 'policyDigest', {
      enumerable: true,
      get: () => (reads++ === 0 ? HEX : 'x'),
    });
    const result = await tzun.capture(decision, { signoffExpectation: expectation as { policyDigest: string } });
    expect(result.stored).toBe(true);
    expect(result.envelope.payload.signoffExpectation).toEqual({ policyDigest: HEX });
    expect(reads).toBe(1);
  });

  const refused: Array<[string, unknown, RegExp]> = [
    ['a string', 'required', /must be null or an object/],
    ['an unknown member', { policyDigest: HEX, by: 'x' }, /exactly the member policyDigest/],
    ['an uppercase digest', { policyDigest: HEX.toUpperCase() }, /policyDigest must be 64 lowercase hex/],
    ['a short digest', { policyDigest: 'abc' }, /policyDigest must be 64 lowercase hex/],
    ['a session slot the caller did not claim', { statementDigest: HEX, sessionSeq: 1 }, /only the capture that claimed the slot/],
    ['a malformed session slot', { statementDigest: HEX, sessionSeq: 0 }, /sessionSeq must be a safe integer of at least 1/],
  ];

  it.each(refused)('%s is a validation_failure, refused before anything is built', async (_label, value, reason) => {
    const store = jest.spyOn(tzun.getStorage(), 'store');
    const storeFailure = jest.spyOn(tzun.getStorage(), 'storeFailure');
    const result = await tzun.capture(decision, { signoffExpectation: value } as CaptureOptions);
    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('validation_failure');
    expect(result.failure?.diagnosticMetadata.field).toBe('signoffExpectation');
    expect(String(result.failure?.diagnosticMetadata.message)).toMatch(reason);
    expect(store).not.toHaveBeenCalled();
    expect((storeFailure.mock.calls[0][0] as FailureRecord).failureType).toBe('validation_failure');

    // No sequence number was taken.
    const ok = await tzun.capture(decision);
    expect(ok.envelope.payload.sequenceNumber).toBe(1);
  });
});

describe('a prepared capture carries the expectation its ceremony signed over', () => {
  let tzun: Tzun;
  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev' });
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('prepareAssertionChallenge hashes it, and the capture stores the same digest', async () => {
    const prepared = await tzun.prepareAssertionChallenge(decision, { signoffExpectation: { policyDigest: HEX } });
    expect(prepared.signoffExpectation).toEqual({ policyDigest: HEX });
    const result = await tzun.capture(decision, { prepared });
    expect(result.stored).toBe(true);
    expect(result.envelope.integrity.canonicalDigest).toBe(prepared.digest);
    expect(result.envelope.payload.signoffExpectation).toEqual({ policyDigest: HEX });
  });

  it('a per-record signature over the record meets { policyDigest }', async () => {
    const prepared = await tzun.prepareAssertionChallenge(decision, { signoffExpectation: { policyDigest: HEX } });
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: webauthnChallengeForDigest(prepared.digest) }),
    ).toString('base64url');
    const result = await tzun.capture(
      {
        ...decision,
        attestationInputs: {
          webauthnAssertion: { signature: 'c2ln', credentialKeyId: 'cred', algorithm: 'ES256', clientDataJSON },
        },
      },
      { prepared },
    );
    expect(result.stored).toBe(true);
    const verdict = await tzun.verify(result.envelope.payload.evidenceId);
    expect(verdict.signoffExpectationValid).toBe(true);
  });

  it('prepareAssertionChallenge hands back a copy, and a prepared capture hashes the value it was called with', async () => {
    const expectation = { policyDigest: HEX };
    const prepared = await tzun.prepareAssertionChallenge(decision, { signoffExpectation: expectation });
    expect(prepared.signoffExpectation).not.toBe(expectation);
    expectation.policyDigest = 'NOT-HEX';
    expect(prepared.signoffExpectation).toEqual({ policyDigest: HEX });

    const pending = tzun.capture(decision, { prepared });
    (prepared.signoffExpectation as { policyDigest: string }).policyDigest = 'NOT-HEX';
    const result = await pending;
    expect(result.stored).toBe(true);
    expect(result.envelope.integrity.canonicalDigest).toBe(prepared.digest);
    expect(result.envelope.payload.signoffExpectation).toEqual({ policyDigest: HEX });
  });

  it('the same expectation given again is accepted; a different one is refused', async () => {
    const prepared = await tzun.prepareAssertionChallenge(decision, { signoffExpectation: { policyDigest: HEX } });
    const differs = await tzun.capture(decision, { prepared, signoffExpectation: null });
    expect(differs.failure?.failureType).toBe('validation_failure');
    expect(differs.failure?.diagnosticMetadata.field).toBe('signoffExpectation');
    expect(String(differs.failure?.diagnosticMetadata.message)).toMatch(/differs from prepared\.signoffExpectation/);

    const same = await tzun.capture(decision, { prepared, signoffExpectation: { policyDigest: HEX } });
    expect(same.stored).toBe(true);
  });

  it('a prepared value from before 0.7.0 (no signoffExpectation) reads as null', async () => {
    const prepared = await tzun.prepareAssertionChallenge(decision);
    const { signoffExpectation: _drop, ...older } = prepared;
    const result = await tzun.capture(decision, { prepared: older as typeof prepared });
    expect(result.stored).toBe(true);
    expect(result.envelope.integrity.canonicalDigest).toBe(prepared.digest);
  });

  it('a prepared value naming a session slot is refused', async () => {
    const prepared = await tzun.prepareAssertionChallenge(decision);
    const result = await tzun.capture(decision, {
      prepared: {
        ...prepared,
        signoffExpectation: { statementDigest: HEX, sessionSeq: 2 },
      } as unknown as PreparedAssertionChallenge,
    });
    expect(result.failure?.diagnosticMetadata.field).toBe('prepared.signoffExpectation');
  });

  it('prepareAssertionChallenge refuses a malformed expectation', async () => {
    await expect(
      tzun.prepareAssertionChallenge(decision, { signoffExpectation: { policyDigest: 'x' } }),
    ).rejects.toThrow(/policyDigest must be 64 lowercase hex/);
  });
});

describe('the 0.7.0 store rule: the first record decides', () => {
  const current = (): EvidenceEnvelope => assembleEnvelope(decision);
  const altered = (env: EvidenceEnvelope): EvidenceEnvelope => {
    env.payload.reason = 'rewritten';
    return env;
  };
  const never = async (): Promise<unknown> => {
    throw new Error('the newest record is not needed here');
  };

  it('an empty store passes', async () => {
    await expect(refuseOutdatedStore(null, never)).resolves.toBeUndefined();
  });

  it('a first record from before 0.7.0 refuses the store, naming it, whatever the newest is', async () => {
    const first = recordFrom06(1);
    await expect(refuseOutdatedStore(first, never)).rejects.toMatchObject({
      code: 'store_schema_outdated',
      evidenceId: first.payload.evidenceId,
    });
  });

  it('a first record 0.7.0 wrote passes, and an old-format record after it does not count', async () => {
    await expect(refuseOutdatedStore(current(), never)).resolves.toBeUndefined();
    await expect(refuseOutdatedStore(altered(current()), never)).resolves.toBeUndefined();
  });

  it('an old first record that was altered defers to the newest record', async () => {
    const newest = recordFrom06(2);
    await expect(refuseOutdatedStore(altered06(recordFrom06(1)), async () => newest)).rejects.toMatchObject({
      evidenceId: newest.payload.evidenceId,
    });
    await expect(
      refuseOutdatedStore(altered06(recordFrom06(1)), async () => altered06(recordFrom06(2))),
    ).resolves.toBeUndefined();
  });

  it('a first record a 0.7 release wrote refuses the store, naming it and its generation', async () => {
    const first = recordFrom06(1, undefined, '0.7');
    await expect(refuseOutdatedStore(first, never)).rejects.toMatchObject({
      code: 'store_schema_outdated',
      evidenceId: first.payload.evidenceId,
      generation: '0.7',
    });
  });
});

describe('SQLite: a store a release before 0.7.0 wrote is refused at open, and left as it was', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-signoff-expectation-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  /** The file's bytes and its schema, read without writing. */
  function fingerprint(dbPath: string): { bytes: string; schema: unknown } {
    const db = new Database(dbPath, { readonly: true, fileMustExist: true });
    try {
      return { bytes: createHash('sha256').update(readFileSync(dbPath)).digest('hex'), schema: sqliteSchemaSnapshot(db) };
    } finally {
      db.close();
    }
  }

  async function oldStore(dbPath: string, records: EvidenceEnvelope[]): Promise<void> {
    const old = new SqliteStorageAdapter(dbPath);
    for (const record of records) await old.store(record);
    await old.close();
  }

  it('Tzun.init throws StoreSchemaOutdatedError naming the first record, and changes no byte', async () => {
    const dbPath = join(dir, 'old.db');
    const first = recordFrom06(1);
    await oldStore(dbPath, [first, recordFrom06(2, first.integrity.canonicalDigest)]);
    const before = fingerprint(dbPath);

    await expect(Tzun.init({ mode: 'dev', dbPath })).rejects.toBeInstanceOf(StoreSchemaOutdatedError);
    await expect(Tzun.init({ mode: 'dev', dbPath })).rejects.toMatchObject({
      code: 'store_schema_outdated',
      retryable: false,
      evidenceId: first.payload.evidenceId,
    });
    expect(fingerprint(dbPath)).toEqual(before);
  });

  // A refused open writes nothing, even to a store shaped as 0.5.0 wrote it,
  // which lacks the chain-log tables: it mints no store identity, creates no
  // chain logs, backfills no leaves and adds no table, trigger or row.
  it('a store shaped as 0.5.0 wrote it gains no table, trigger or row', async () => {
    const dbPath = join(dir, 'v05.db');
    await oldStore(dbPath, [recordFrom06(1)]);
    const db = new Database(dbPath);
    stripLogSchemaSqlite(db);
    db.close();
    const before = fingerprint(dbPath);

    await expect(Tzun.init({ mode: 'dev', dbPath })).rejects.toBeInstanceOf(StoreSchemaOutdatedError);
    expect(fingerprint(dbPath)).toEqual(before);
  });

  it('an old store whose newest record was altered is still refused', async () => {
    const dbPath = join(dir, 'old-altered-head.db');
    const first = recordFrom06(1);
    await oldStore(dbPath, [first, altered06(recordFrom06(2, first.integrity.canonicalDigest))]);
    await expect(Tzun.init({ mode: 'dev', dbPath })).rejects.toMatchObject({ evidenceId: first.payload.evidenceId });
  });

  it('an old store whose first record was altered is refused by its newest', async () => {
    const dbPath = join(dir, 'old-altered-first.db');
    const first = altered06(recordFrom06(1));
    const newest = recordFrom06(2, first.integrity.canonicalDigest);
    await oldStore(dbPath, [first, newest]);
    await expect(Tzun.init({ mode: 'dev', dbPath })).rejects.toMatchObject({ evidenceId: newest.payload.evidenceId });
  });

  // One forged old-format row appended to a store 0.7.0 wrote does not make
  // Tzun.init() refuse the store and tell the operator to abandon it: the
  // first record decides, and the verifiers report the forged record.
  it('a store 0.7.0 wrote opens with an old-format record appended to it; the verifiers report that record', async () => {
    const dbPath = join(dir, 'new-forged.db');
    const a = await Tzun.init({ mode: 'dev', dbPath });
    for (let i = 0; i < 3; i++) await a.capture(decision);
    await a.close();
    const forged = recordFrom06(4);
    const writer = new SqliteStorageAdapter(dbPath);
    await writer.store(forged);
    await writer.close();

    const b = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const verdict = await b.verify(forged.payload.evidenceId);
      expect(verdict.verified).toBe(false);
      // Its digest does not recompute, so its expectation is not read.
      expect(verdict.signoffExpectationValid).toBeNull();
      expect(verdict.signoffExpectationReason).toBe('digest_invalid');
    } finally {
      await b.close();
    }
  });

  it('a store 0.7.0 wrote opens again', async () => {
    const dbPath = join(dir, 'new.db');
    const a = await Tzun.init({ mode: 'dev', dbPath });
    await a.capture(decision);
    await a.close();
    const b = await Tzun.init({ mode: 'dev', dbPath });
    expect((await b.capture(decision)).envelope.payload.sequenceNumber).toBe(2);
    await b.close();
  });

  it('an empty store, and a path with no file yet, open: they hold nothing the store check could misread', async () => {
    const dbPath = join(dir, 'empty.db');
    const empty = new SqliteStorageAdapter(dbPath);
    await empty.close();
    const tzun = await Tzun.init({ mode: 'dev', dbPath });
    expect((await tzun.capture(decision)).stored).toBe(true);
    await tzun.close();
    const fresh = await Tzun.init({ mode: 'dev', dbPath: join(dir, 'none-yet.db') });
    expect((await fresh.capture(decision)).stored).toBe(true);
    await fresh.close();
  });
});

describe('an idempotency key replays only the expectation it was first used with', () => {
  let dir: string;
  let tzun: Tzun;
  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-signoff-expectation-idem-'));
    tzun = await Tzun.init({ mode: 'dev', dbPath: join(dir, 'store.db') });
  });
  afterEach(async () => {
    await tzun.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('a retry that adds an expectation is a conflict, not a replay of a record that owes nothing', async () => {
    const first = await tzun.capture(decision, { idempotencyKey: 'k1' });
    expect(first.stored).toBe(true);
    const retry = await tzun.capture(decision, { idempotencyKey: 'k1', signoffExpectation: { policyDigest: HEX } });
    expect(retry.stored).toBe(false);
    expect(retry.failure?.failureType).toBe('idempotency_conflict');
  });

  it('a retry that names another policy is a conflict; the same policy replays', async () => {
    const first = await tzun.capture(decision, { idempotencyKey: 'k2', signoffExpectation: { policyDigest: HEX } });
    expect(first.stored).toBe(true);
    const other = await tzun.capture(decision, { idempotencyKey: 'k2', signoffExpectation: { policyDigest: 'd'.repeat(64) } });
    expect(other.failure?.failureType).toBe('idempotency_conflict');
    const same = await tzun.capture(decision, { idempotencyKey: 'k2', signoffExpectation: { policyDigest: HEX } });
    expect(same.stored).toBe(true);
    expect(same.replayed).toBe(true);
    expect(same.envelope.payload.signoffExpectation).toEqual({ policyDigest: HEX });
  });

  it('with no expectation on either call, a retry replays the first record', async () => {
    const first = await tzun.capture(decision, { idempotencyKey: 'k3' });
    const again = await tzun.capture(decision, { idempotencyKey: 'k3', signoffExpectation: null });
    expect(again.replayed).toBe(true);
    expect(again.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
  });
});

describe('a stripped signature swapped for junk is not a signature carried', () => {
  it('Tzun.verify on a { policyDigest } record filled with a junk batch block and assertion: false, signoff_unbound', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    try {
      const captured = await tzun.capture(decision, { signoffExpectation: { policyDigest: HEX } });
      const id = captured.envelope.payload.evidenceId;
      expect((await tzun.verify(id)).signoffExpectationReason).toBe('signature_missing');
      await tzun.getStorage().updateAttestation(id, {
        signoff: { statement: { mode: 'batch' } },
        webauthnAssertion: { credentialId: 'x', authenticatorData: 'AA', clientDataJSON: 'e30', signature: 'AA' },
      } as never, 'partial');
      const result = await tzun.verify(id);
      expect(result.verified).toBe(true);
      expect(result.signoffExpectationValid).toBe(false);
      expect(result.signoffExpectationReason).toBe('signoff_unbound');
    } finally {
      await tzun.close();
    }
  });
});

describe.each(['memory', 'sqlite'] as const)('a read carries the expectation check in its verdict (%s)', (leg) => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-signoff-expectation-verdict-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('get() and list() report signoffExpectation beside the integrity checks, outside status', async () => {
    const tzun = await Tzun.init(leg === 'memory' ? { mode: 'dev' } : { mode: 'dev', dbPath: join(dir, 'store.db') });
    try {
      const owed = await tzun.capture(decision, { signoffExpectation: { policyDigest: HEX } });
      const plain = await tzun.capture(decision);
      const read = await tzun.get(owed.envelope.payload.evidenceId);
      expect(read!.verdict.status).toBe('valid');
      expect(read!.verdict.signoffExpectation).toEqual({ valid: null, reason: 'signature_missing' });

      // A session sign-off transplanted onto a record that names no session.
      await tzun.getStorage().updateAttestation(plain.envelope.payload.evidenceId, {
        signoff: { statement: { mode: 'session' }, sessionSeq: 1 },
        webauthnAssertion: { credentialKeyId: 'x', algorithm: 'ES256', clientDataJSON: 'e30', signature: 'AA' },
      } as never, 'partial');
      const listed = await tzun.list();
      const byId = new Map(listed.map((r) => [r.envelope.payload.evidenceId, r.verdict]));
      expect(byId.get(plain.envelope.payload.evidenceId)!.signoffExpectation).toEqual({
        valid: false,
        reason: 'session_signoff_not_expected',
      });
      expect(byId.get(plain.envelope.payload.evidenceId)!.status).toBe('valid');
    } finally {
      await tzun.close();
    }
  });
});

// The signature-stripping tamper: a record that owed a signature, stripped of
// it, with its { policyDigest } rewritten to null. Its digest no longer
// recomputes, so the rewritten value is not read: verify() and every read
// report null, digest_invalid, never true.
describe('a record whose digest does not recompute: its expectation is not read (sqlite)', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-signoff-expectation-digest-invalid-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('verify(), get() and list() report null, digest_invalid on an expectation rewritten to null', async () => {
    const dbPath = join(dir, 'store.db');
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const genesis = await a.capture(decision);
    await a.close();

    const forged = assembleEnvelope(decision, { previousDigest: genesis.envelope.integrity.canonicalDigest, sequenceNumber: 2, signoffExpectation: { policyDigest: HEX } });
    forged.payload.signoffExpectation = null;
    const writer = new SqliteStorageAdapter(dbPath);
    await writer.store(forged);
    await writer.close();

    const b = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const id = forged.payload.evidenceId;
      const verdict = await b.verify(id);
      expect(verdict.verified).toBe(false);
      expect(verdict.chainLinkValid).toBe(true);
      expect(verdict.signoffExpectationValid).toBeNull();
      expect(verdict.signoffExpectationReason).toBe('digest_invalid');

      const read = await b.get(id);
      expect(read!.verdict.digest.status).toBe('invalid');
      expect(read!.verdict.signoffExpectation).toEqual({ valid: null, reason: 'digest_invalid' });
      const listed = await b.list();
      const byId = new Map(listed.map((r) => [r.envelope.payload.evidenceId, r.verdict]));
      expect(byId.get(id)!.signoffExpectation).toEqual({ valid: null, reason: 'digest_invalid' });
      expect(byId.get(genesis.envelope.payload.evidenceId)!.signoffExpectation).toEqual({ valid: true });
    } finally {
      await b.close();
    }
  });
});

(PG_TESTS_ENABLED ? describe : describe.skip)('Postgres: a store a release before 0.7.0 wrote is refused at open, and left as it was', () => {
  const schema = pgSuiteSchema('signoff_expectation_store_refusal');
  let pool: Pool;
  beforeAll(() => {
    pool = new Pool({ connectionString: schema.url });
  });
  afterAll(async () => {
    await pool.end();
  });

  async function oldStore(records: EvidenceEnvelope[]): Promise<void> {
    const old = new PostgresStorageAdapter(schema.url);
    await old.ensureTables();
    for (const record of records) await old.store(record);
    await old.close();
  }

  it('Tzun.init throws StoreSchemaOutdatedError naming the first record, and changes no schema object; a new database opens', async () => {
    await schema.reset();
    const first = recordFrom06(1);
    await oldStore([first, recordFrom06(2, first.integrity.canonicalDigest)]);
    const before = await postgresSchemaSnapshot(pool, schema.name);

    await expect(Tzun.init({ mode: 'dev', dbUrl: schema.url })).rejects.toMatchObject({
      code: 'store_schema_outdated',
      evidenceId: first.payload.evidenceId,
    });
    expect(await postgresSchemaSnapshot(pool, schema.name)).toEqual(before);

    await schema.reset();
    const fresh = await Tzun.init({ mode: 'dev', dbUrl: schema.url });
    expect((await fresh.capture(decision)).stored).toBe(true);
    await fresh.close();
  });

  it('a store shaped as 0.5.0 wrote it gains no table, trigger, function or row', async () => {
    await schema.reset();
    await oldStore([recordFrom06(1)]);
    const client = new Client({ connectionString: schema.url });
    await client.connect();
    try {
      await stripLogSchemaPostgres(client);
    } finally {
      await client.end();
    }
    const before = await postgresSchemaSnapshot(pool, schema.name);
    const rows = async () =>
      (await pool.query(`SELECT count(*)::int AS n FROM ${schema.name}.envelopes`)).rows[0].n as number;
    const rowsBefore = await rows();

    await expect(Tzun.init({ mode: 'dev', dbUrl: schema.url })).rejects.toBeInstanceOf(StoreSchemaOutdatedError);
    expect(await postgresSchemaSnapshot(pool, schema.name)).toEqual(before);
    expect(await rows()).toBe(rowsBefore);
  });

  it('a store 0.7.0 wrote opens with an old-format record appended to it', async () => {
    await schema.reset();
    const a = await Tzun.init({ mode: 'dev', dbUrl: schema.url });
    for (let i = 0; i < 3; i++) await a.capture(decision);
    await a.close();
    const writer = new PostgresStorageAdapter(schema.url);
    await writer.store(recordFrom06(4));
    await writer.close();

    const b = await Tzun.init({ mode: 'dev', dbUrl: schema.url });
    await b.close();
  });

  it('ensureTables() indexes envelopes in the order the store check and head() read them', async () => {
    await schema.reset();
    const a = await Tzun.init({ mode: 'dev', dbUrl: schema.url });
    await a.close();
    const index = await pool.query(
      `SELECT indexdef FROM pg_indexes WHERE schemaname = $1 AND tablename = 'envelopes' AND indexname = 'idx_envelopes_created_at'`,
      [schema.name],
    );
    expect(index.rows.map((r) => (r.indexdef as string).split(`${schema.name}.`).join(''))).toEqual([
      'CREATE INDEX idx_envelopes_created_at ON envelopes USING btree (created_at, evidence_id)',
    ]);
  });
});
