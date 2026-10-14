/**
 * Storage-adapter conformance contract.
 *
 * One `it` per observable behaviour, each named for the fact it asserts, run
 * unchanged against memory, SQLite and Postgres by `adapters.test.ts`.
 * Postgres — the production backend — is the reference, and the other
 * adapters match it; the two exceptions are called out in-line as asserted
 * divergences (a documented difference that silently disappears is as much a
 * drift as one that appears).
 *
 * Behaviour names are shared with the Python twin,
 * `python/tests/storage/test_conformance.py`, so the two matrices can be
 * compared by name.
 */
import {
  ChainConflictError,
  ChainSealedError,
  EvidenceEnvelope,
  StorageAdapter,
  computeCustodyEntryHash,
  verifyCustodyTrail,
} from '@tzun/engine';
import { AmbiguousActiveChainError, NoActiveChainError } from '@tzun/engine';
import { DuplicateRecordError, MissingReferenceError } from '../../../src/storage/append-only';
import { InvalidPaginationError } from '../../../src/storage/pagination-guard';
import { refusal } from '../helpers/log-store-backends';
import {
  makeAnnotation,
  makeChain,
  makeDescriptor,
  makeDescriptorAnnotation,
  makeEnvelope,
  makeFork,
  makeIncident,
  makeRelink,
} from './fixtures';

export type Backend = 'memory' | 'sqlite' | 'postgres';

/** What an adapter cannot be made to agree on, stated so it can be asserted. */
export interface AdapterCaps {
  backend: Backend;
}

/** Every method the conformance suite exercises; all in-tree adapters have them. */
export type ConformantAdapter = Required<
  Pick<
    StorageAdapter,
    | 'registerModelDescriptor'
    | 'getModelDescriptor'
    | 'getEnrichedModelDescriptor'
    | 'listModelDescriptors'
    | 'listDescendantDescriptors'
    | 'appendModelDescriptorAnnotation'
    | 'listModelDescriptorAnnotations'
    | 'setModelDescriptorAlias'
    | 'resolveModelDescriptorAlias'
    | 'head'
    | 'storeIdempotent'
    | 'close'
  >
> &
  StorageAdapter;

export interface AdapterUnderTest {
  factory: () => Promise<{ adapter: StorageAdapter; teardown: () => Promise<void> }>;
  caps: AdapterCaps;
}

/**
 * Detach a value from anything the adapter might still hold. Used on the
 * EXPECTED side of comparisons so that a fixture object the test later mutates
 * cannot make an assertion pass by aliasing.
 */
const snapshot = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

const ids = (list: EvidenceEnvelope[]): string[] => list.map((e) => e.payload.evidenceId);


/**
 * Arm the demo-tamper hooks on an adapter. The guard arms an EMPTY store only
 * when the adapter can show it is loopback-local; the Postgres leg points at a
 * container IP, so it goes through the one-shot bootstrap valve, which the
 * guard consumes. Both outcomes log a structured line on stderr; silenced here.
 */
async function armDemoHooks(adapter: StorageAdapter): Promise<void> {
  const arm = (adapter as unknown as { armDemoTamperHooks(): Promise<void> }).armDemoTamperHooks;
  const spy = jest.spyOn(console, 'error').mockImplementation(() => { /* silenced */ });
  const saved = process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
  process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
  try {
    await arm.call(adapter);
  } finally {
    if (saved === undefined) delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
    else process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = saved;
    spy.mockRestore();
  }
}

/**
 * Remove a record's revision rows to simulate a record captured by an SDK
 * older than 0.3.16 — the migration case, which has no other way to arise in
 * a test. It steps around the append-only guards EXPLICITLY (SQLite: drop and
 * re-create the triggers around the delete; Postgres: the same
 * transaction-scoped `session_replication_role = 'replica'` bypass
 * `deleteEnvelopeForDemo` uses), because the whole point of the guards is
 * that there is no ordinary way to do this.
 */
async function deleteRevisionRowsForTest(adapter: StorageAdapter, evidenceId: string): Promise<void> {
  const memoryRows = (adapter as unknown as { envelopeRevisions?: Map<string, unknown> }).envelopeRevisions;
  if (memoryRows instanceof Map) {
    memoryRows.delete(evidenceId);
    return;
  }
  const sqliteDb = (adapter as unknown as { db?: import('better-sqlite3').Database }).db;
  if (sqliteDb) {
    sqliteDb.exec('DROP TRIGGER IF EXISTS envelope_revisions_block_delete');
    sqliteDb.prepare('DELETE FROM envelope_revisions WHERE evidence_id = ?').run(evidenceId);
    sqliteDb.exec(`
      CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_delete
        BEFORE DELETE ON envelope_revisions
        BEGIN SELECT RAISE(ABORT, 'envelope_revisions rows are append-only (DELETE refused)'); END;
    `);
    return;
  }
  const pool = (adapter as unknown as { pool?: import('pg').Pool }).pool;
  if (!pool) throw new Error('deleteRevisionRowsForTest: unrecognised adapter');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query('DELETE FROM envelope_revisions WHERE evidence_id = $1', [evidenceId]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => { /* ignore */ });
    throw err;
  } finally {
    client.release();
  }
}

export function describeStorageConformance(
  name: string,
  factory: AdapterUnderTest['factory'],
  caps: AdapterCaps,
): void {
  describe(`storage conformance: ${name}`, () => {
    let adapter: ConformantAdapter;
    let teardown: () => Promise<void>;

    beforeEach(async () => {
      const made = await factory();
      adapter = made.adapter as ConformantAdapter;
      teardown = made.teardown;
    });

    afterEach(async () => {
      await teardown();
    });

    // ── Evidence round trip ───────────────────────────────────────────────

    describe('evidence round trip', () => {
      it('store then retrieve returns an equal envelope', async () => {
        const env = makeEnvelope({ evidenceId: 'rt-1' });
        await adapter.store(env);
        expect(await adapter.retrieve('rt-1')).toEqual(snapshot(env));
      });

      it('retrieve of an unknown evidenceId is null', async () => {
        expect(await adapter.retrieve('nope')).toBeNull();
      });

      it('a duplicate evidenceId is refused with the append-only message', async () => {
        const env = makeEnvelope({ evidenceId: 'dup-1' });
        await adapter.store(env);
        const attempt = adapter.store(makeEnvelope({ evidenceId: 'dup-1', sequenceNumber: 2 }));
        await expect(attempt).rejects.toThrow('Evidence record "dup-1" already exists. Storage is append-only.');
        await expect(attempt).rejects.toThrow(DuplicateRecordError);
        // And the original is untouched.
        expect((await adapter.retrieve('dup-1'))!.payload.sequenceNumber).toBe(1);
      });

      it('getChainForRecord names the chain the record was stored under, null when unknown', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'c-default' }));
        await adapter.store(makeEnvelope({ evidenceId: 'c-a', sequenceNumber: 1 }), 'chain-a');
        expect(await adapter.getChainForRecord('c-default')).toBe('default');
        expect(await adapter.getChainForRecord('c-a')).toBe('chain-a');
        expect(await adapter.getChainForRecord('missing')).toBeNull();
      });

      it('getChainLength counts the chain, or the whole store when no chain is given', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'l-1' }), 'chain-a');
        await adapter.store(makeEnvelope({ evidenceId: 'l-2', sequenceNumber: 2 }), 'chain-a');
        await adapter.store(makeEnvelope({ evidenceId: 'l-3' }), 'chain-b');
        expect(await adapter.getChainLength('chain-a')).toBe(2);
        expect(await adapter.getChainLength('chain-b')).toBe(1);
        expect(await adapter.getChainLength()).toBe(3);
      });
    });

    // ── Chain head CAS, sealed chains, chain_state residues ───────────────

    describe('chain head', () => {
      it('expectChainHead against a stale head is refused with ChainConflictError', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'h-1', digest: '11'.repeat(32) }));
        const attempt = adapter.store(
          makeEnvelope({ evidenceId: 'h-2', sequenceNumber: 2 }),
          'default',
          { expectChainHead: { sequence: 0, digest: null } },
        );
        await expect(attempt).rejects.toThrow(ChainConflictError);
        await expect(attempt).rejects.toMatchObject({ code: 'chain_conflict' });
        expect(await adapter.retrieve('h-2')).toBeNull();
      });

      it('expectChainHead that matches the live head is accepted', async () => {
        const first = makeEnvelope({ evidenceId: 'h-1', digest: '11'.repeat(32) });
        await adapter.store(first);
        await expect(
          adapter.store(makeEnvelope({ evidenceId: 'h-2', sequenceNumber: 2 }), 'default', {
            expectChainHead: { sequence: 1, digest: first.integrity.canonicalDigest },
          }),
        ).resolves.toBeUndefined();
      });

      it('an empty-chain expectation against an empty store is accepted', async () => {
        await expect(
          adapter.store(makeEnvelope({ evidenceId: 'h-1' }), 'default', {
            expectChainHead: { sequence: 0, digest: null },
          }),
        ).resolves.toBeUndefined();
      });

      // The refusal is typed: the engine's ChainSealedError,
      // naming the chain and when it was sealed, from every adapter's guard —
      // so a caller branches on `code`, not on the message.
      it('an append to a sealed chain is refused with ChainSealedError naming the chain and its seal', async () => {
        await adapter.storeChain(makeChain({ chainId: 'sealed-typed' }));
        await adapter.sealChain('sealed-typed', '2026-04-04T11:00:00.000Z');
        const refusal = await adapter.store(makeEnvelope({ evidenceId: 'st-1' }), 'sealed-typed').then(
          () => { throw new Error('the append to a sealed chain went through'); },
          (e: unknown) => e,
        );
        expect(refusal).toBeInstanceOf(ChainSealedError);
        expect(refusal).toMatchObject({
          code: 'chain_sealed',
          retryable: false,
          chainId: 'sealed-typed',
          sealedAt: '2026-04-04T11:00:00.000Z',
        });
        expect(await adapter.retrieve('st-1')).toBeNull();
      });

      it('a sealed chain refuses new records', async () => {
        await adapter.storeChain(makeChain({ chainId: 'sealed-1' }));
        await adapter.store(makeEnvelope({ evidenceId: 's-1' }), 'sealed-1');
        await adapter.sealChain('sealed-1', '2026-04-04T11:00:00.000Z');
        await expect(adapter.store(makeEnvelope({ evidenceId: 's-2', sequenceNumber: 2 }), 'sealed-1'))
          .rejects.toThrow(/sealed/i);
        expect(await adapter.retrieve('s-2')).toBeNull();
        expect(await adapter.getChainLength('sealed-1')).toBe(1);
      });

      it('a chain with no identity row still accepts records', async () => {
        await expect(adapter.store(makeEnvelope({ evidenceId: 'implicit-1' }), 'never-registered'))
          .resolves.toBeUndefined();
      });

      it('getLastDigest and getLastSequence start empty and follow the last store', async () => {
        expect(await adapter.getLastDigest()).toBeNull();
        expect(await adapter.getLastSequence()).toBe(0);
        await adapter.store(makeEnvelope({ evidenceId: 'g-1', digest: 'aa'.repeat(32) }));
        expect(await adapter.getLastDigest()).toBe('aa'.repeat(32));
        expect(await adapter.getLastSequence()).toBe(1);
        expect(typeof (await adapter.getLastSequence())).toBe('number');
      });

      it('no chain id names the default chain, the one store() writes to', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'd-1', digest: 'ab'.repeat(32) }));
        expect(await adapter.getLastDigest('default')).toBe('ab'.repeat(32));
        expect(await adapter.getLastSequence('default')).toBe(1);
        expect(await adapter.getLastDigest()).toBe(await adapter.getLastDigest('default'));
        expect(await adapter.getLastSequence()).toBe(await adapter.getLastSequence('default'));
      });

      it('each chain has its own head; a write to one does not move another', async () => {
        for (let i = 1; i <= 3; i++) {
          await adapter.store(makeEnvelope({ evidenceId: `pre-${i}`, sequenceNumber: i, digest: `${'0'.repeat(63)}${i}` }));
        }
        // The forked chain restarts at 1 in its OWN counter. A single
        // store-wide head would let this record move it, and the next append
        // to either chain would then link from the wrong record.
        await adapter.store(makeEnvelope({ evidenceId: 'post-1', sequenceNumber: 1, digest: 'f'.repeat(64) }), 'forked');
        expect(await adapter.getLastSequence('forked')).toBe(1);
        expect(await adapter.getLastDigest('forked')).toBe('f'.repeat(64));
        expect(await adapter.getLastSequence()).toBe(3);
        expect(await adapter.getLastDigest()).toBe(`${'0'.repeat(63)}3`);

        // A chain nothing has written to has no head at all — which is a
        // different fact from "reached sequence 0", and what lets a verifier
        // tell an empty chain from one whose records were deleted.
        expect(await adapter.getLastSequence('untouched')).toBe(0);
        expect(await adapter.getLastDigest('untouched')).toBeNull();
      });

      it('a chain head is a high-water mark, and a position the chain has passed takes no second record', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'hw-1', sequenceNumber: 1 }), 'hw');
        await adapter.store(makeEnvelope({ evidenceId: 'hw-2', sequenceNumber: 2 }), 'hw');
        await adapter.store(makeEnvelope({ evidenceId: 'hw-3', sequenceNumber: 3, digest: 'e'.repeat(64) }), 'hw');
        // A low-level store at a position the chain has already passed: the
        // position holds a record, so this one is refused.
        await expect(
          adapter.store(makeEnvelope({ evidenceId: 'hw-1b', sequenceNumber: 1, digest: 'd'.repeat(64) }), 'hw'),
        ).rejects.toMatchObject({ code: 'evidence_log_refused', reason: 'position_taken' });
        expect(await adapter.retrieve('hw-1b')).toBeNull();
        expect(await adapter.getLastSequence('hw')).toBe(3);
        expect(await adapter.getLastDigest('hw')).toBe('e'.repeat(64));
      });

      it('resetChainState refuses a chain whose evidence log holds leaves, and touches no chain', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'r-1', digest: 'ac'.repeat(32) }));
        await adapter.store(makeEnvelope({ evidenceId: 'r-2', digest: 'ad'.repeat(32) }), 'other');

        await expect(adapter.resetChainState()).rejects.toMatchObject({ code: 'chain_state_reset_refused', chainId: 'default' });
        await expect(adapter.resetChainState('other')).rejects.toMatchObject({ code: 'chain_state_reset_refused', chainId: 'other' });
        expect(await adapter.getLastDigest()).toBe('ac'.repeat(32));
        expect(await adapter.getLastSequence()).toBe(1);
        expect(await adapter.getLastDigest('other')).toBe('ad'.repeat(32));
        expect(await adapter.getLastSequence('other')).toBe(1);

        // The next record takes the next position, and gets its leaf.
        await adapter.store(makeEnvelope({ evidenceId: 'r-3', sequenceNumber: 2, digest: 'ae'.repeat(32) }), 'other');
        expect(await adapter.getLastSequence('other')).toBe(2);
      });

      it('a raw DELETE of a logged chain_state row, or an UPDATE lowering its sequence, is refused by the database', async () => {
        if (caps.backend === 'memory') return; // no SQL surface
        await adapter.store(makeEnvelope({ evidenceId: 'raw-1', digest: 'b1'.repeat(32) }), 'raw');
        await adapter.store(makeEnvelope({ evidenceId: 'raw-2', sequenceNumber: 2, digest: 'b2'.repeat(32) }), 'raw');
        const attempts = [
          "DELETE FROM chain_state WHERE chain_id = 'raw'",
          "UPDATE chain_state SET last_sequence = 0 WHERE chain_id = 'raw'",
          "UPDATE chain_state SET last_sequence = 1, last_digest = NULL WHERE chain_id = 'raw'",
        ];
        const sqliteDb = (adapter as unknown as { db?: import('better-sqlite3').Database }).db;
        const pool = (adapter as unknown as { pool?: import('pg').Pool }).pool;
        const run = async (sql: string): Promise<unknown> => (sqliteDb ? sqliteDb.exec(sql) : pool!.query(sql));
        for (const sql of attempts) {
          // By its message, not with rejects.toThrow: a better-sqlite3 error
          // can come from another test file's realm.
          await refusal(() => run(sql), /chain_state_logged/);
        }
        expect(await adapter.getLastSequence('raw')).toBe(2);
        expect(await adapter.getLastDigest('raw')).toBe('b2'.repeat(32));
        // An update that does not lower the sequence passes, and the chain goes on.
        await run("UPDATE chain_state SET last_sequence = last_sequence WHERE chain_id = 'raw'");
        await adapter.store(makeEnvelope({ evidenceId: 'raw-3', sequenceNumber: 3, digest: 'b3'.repeat(32) }), 'raw');
        expect(await adapter.getLastSequence('raw')).toBe(3);
      });

      it('resetChainState clears a chain whose evidence log holds no leaf', async () => {
        await adapter.resetChainState('never-written');
        expect(await adapter.getLastDigest('never-written')).toBeNull();
        expect(await adapter.getLastSequence('never-written')).toBe(0);
      });

      it('expectChainHead compares the TARGET chain head, not the store', async () => {
        const first = makeEnvelope({ evidenceId: 'cas-a1', sequenceNumber: 1, digest: '1a'.repeat(32) });
        await adapter.store(first, 'cas-a', { expectChainHead: { sequence: 0, digest: null } });

        // A second chain's genesis append expects an EMPTY chain, although the
        // store's other chain has just moved. It is accepted: compared against
        // a store-wide head it would be refused, and so would every per-tenant
        // chain's first record.
        const other = makeEnvelope({ evidenceId: 'cas-b1', sequenceNumber: 1, digest: '1b'.repeat(32) });
        await expect(
          adapter.store(other, 'cas-b', { expectChainHead: { sequence: 0, digest: null } }),
        ).resolves.toBeUndefined();

        // And a stale head for the chain being appended to is still refused.
        await expect(
          adapter.store(
            makeEnvelope({ evidenceId: 'cas-a2', sequenceNumber: 2, digest: '1c'.repeat(32) }),
            'cas-a',
            { expectChainHead: { sequence: 0, digest: null } },
          ),
        ).rejects.toMatchObject({ code: 'chain_conflict' });
      });
    });

    // ── Sequence-ordered reads ────────────────────────────────────────────

    describe('sequence reads', () => {
      it('listBySequence defaults its lower bound to 1 and sorts ascending', async () => {
        // Written in sequence order, as a chain always is (its evidence log is dense).
        await adapter.store(makeEnvelope({ evidenceId: 'q-1', sequenceNumber: 1 }));
        await adapter.store(makeEnvelope({ evidenceId: 'q-2', sequenceNumber: 2 }));
        await adapter.store(makeEnvelope({ evidenceId: 'q-3', sequenceNumber: 3 }));
        expect(ids(await adapter.listBySequence())).toEqual(['q-1', 'q-2', 'q-3']);
      });

      it('listBySequence honours both inclusive bounds', async () => {
        for (let i = 1; i <= 5; i++) {
          await adapter.store(makeEnvelope({ evidenceId: `b-${i}`, sequenceNumber: i }));
        }
        expect(ids(await adapter.listBySequence(2, 4))).toEqual(['b-2', 'b-3', 'b-4']);
        expect(ids(await adapter.listBySequence(4))).toEqual(['b-4', 'b-5']);
      });

      it('listBySequence with a chainId returns only that chain; without one it returns every chain', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'a-1', sequenceNumber: 1 }), 'chain-a');
        await adapter.store(makeEnvelope({ evidenceId: 'a-2', sequenceNumber: 2 }), 'chain-a');
        await adapter.store(makeEnvelope({ evidenceId: 'b-1', sequenceNumber: 1 }), 'chain-b');
        expect(ids(await adapter.listBySequence(1, undefined, 'chain-a'))).toEqual(['a-1', 'a-2']);
        expect(ids(await adapter.listBySequence(1, undefined, 'chain-b'))).toEqual(['b-1']);
        expect(ids(await adapter.listBySequence()).sort()).toEqual(['a-1', 'a-2', 'b-1']);
      });

      it('getBySequenceRange is inclusive and chain-scoped', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'ra-1', sequenceNumber: 1 }), 'chain-a');
        await adapter.store(makeEnvelope({ evidenceId: 'ra-2', sequenceNumber: 2 }), 'chain-a');
        await adapter.store(makeEnvelope({ evidenceId: 'rb-1', sequenceNumber: 1 }), 'chain-b');
        await adapter.store(makeEnvelope({ evidenceId: 'rb-2', sequenceNumber: 2 }), 'chain-b');
        expect(ids(await adapter.getBySequenceRange(2, 2, 'chain-a'))).toEqual(['ra-2']);
        expect(ids(await adapter.getBySequenceRange(1, 2, 'chain-a'))).toEqual(['ra-1', 'ra-2']);
      });
    });

    // ── The one permitted mutation ────────────────────────────────────────

    describe('attestation update', () => {
      it('updateAttestation merges artifacts and sets the status; payload and digest are untouched', async () => {
        const env = makeEnvelope({ evidenceId: 'at-1' });
        env.nonRepudiation = { webauthnAssertion: { signature: 'sig', credentialKeyId: 'k', algorithm: 'ES256' } };
        await adapter.store(env);
        await adapter.updateAttestation('at-1', { rfc3161Token: 'tok' }, 'complete');
        const got = (await adapter.retrieve('at-1'))!;
        expect(got.nonRepudiation.rfc3161Token).toBe('tok');
        expect(got.nonRepudiation.webauthnAssertion?.signature).toBe('sig');
        expect(got.attestationStatus).toBe('complete');
        expect(got.payload).toEqual(snapshot(env.payload));
        expect(got.integrity.canonicalDigest).toBe(env.integrity.canonicalDigest);
      });

      // Two schedulers on one store both work the same
      // pending record. Whoever commits second must not replace a token that
      // has already landed: it fills only what is still absent.
      it('fills only what is absent: an artifact already on the record is kept', async () => {
        const env = makeEnvelope({ evidenceId: 'at-fill' });
        env.nonRepudiation = { rfc3161Token: 'first-token' };
        env.attestationStatus = 'partial';
        await adapter.store(env);

        await adapter.updateAttestation(
          'at-fill',
          { rfc3161Token: 'second-token', anchor: { txHash: '0xabc', chain: 'sepolia' } as never },
          'complete',
        );

        const got = (await adapter.retrieve('at-fill'))!;
        expect(got.nonRepudiation.rfc3161Token).toBe('first-token');
        expect(got.nonRepudiation.anchor).toMatchObject({ txHash: '0xabc' });
        expect(got.attestationStatus).toBe('complete');
      });

      it('an update that fills nothing writes nothing, and leaves no revision row', async () => {
        const env = makeEnvelope({ evidenceId: 'at-noop' });
        env.nonRepudiation = { rfc3161Token: 'tok' };
        env.attestationStatus = 'partial';
        await adapter.store(env);
        const before = await adapter.listEnvelopeRevisions('at-noop');

        await adapter.updateAttestation('at-noop', { rfc3161Token: 'other' }, 'partial');

        expect(await adapter.retrieve('at-noop')).toEqual(snapshot(env));
        expect(await adapter.listEnvelopeRevisions('at-noop')).toEqual(before);
      });

      // The retry pass works on at most `batchSize` pending records at a
      // time, oldest first; the limit keeps it from holding every pending
      // record to work on a few of them.
      it('listByAttestationStatus is oldest first and takes a limit', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'p-mid', capturedAt: '2026-03-22T10:00:01.000Z', sequenceNumber: 1, attestationStatus: 'pending' }));
        await adapter.store(makeEnvelope({ evidenceId: 'p-old', capturedAt: '2026-03-22T10:00:00.000Z', sequenceNumber: 2, attestationStatus: 'pending' }));
        await adapter.store(makeEnvelope({ evidenceId: 'p-new', capturedAt: '2026-03-22T10:00:02.000Z', sequenceNumber: 3, attestationStatus: 'pending' }));
        await adapter.store(makeEnvelope({ evidenceId: 'p-done', capturedAt: '2026-03-22T09:00:00.000Z', sequenceNumber: 4, attestationStatus: 'complete' }));

        expect(ids(await adapter.listByAttestationStatus('pending'))).toEqual(['p-old', 'p-mid', 'p-new']);
        expect(ids(await adapter.listByAttestationStatus('pending', 2))).toEqual(['p-old', 'p-mid']);
        expect(ids(await adapter.listByAttestationStatus('pending', 99))).toEqual(['p-old', 'p-mid', 'p-new']);
        expect(ids(await adapter.listByAttestationStatus('pending', 0))).toEqual([]);
        expect(ids(await adapter.listByAttestationStatus('complete'))).toEqual(['p-done']);
      });

      it('listByAttestationStatus refuses a limit that is not a non-negative integer', async () => {
        for (const bad of [-1, 1.5, Number.NaN, '2' as unknown as number]) {
          await expect(adapter.listByAttestationStatus('pending', bad)).rejects.toBeInstanceOf(InvalidPaginationError);
        }
      });

      it('a completed record is never walked backwards by a later writer', async () => {
        const env = makeEnvelope({ evidenceId: 'at-done' });
        env.nonRepudiation = { rfc3161Token: 'tok' };
        env.attestationStatus = 'complete';
        await adapter.store(env);

        await adapter.updateAttestation(
          'at-done',
          { anchor: { txHash: '0xdef', chain: 'sepolia' } as never },
          'pending',
        );

        expect((await adapter.retrieve('at-done'))!.attestationStatus).toBe('complete');
      });

      it('updateAttestation on an unknown record throws the not-found message', async () => {
        await expect(adapter.updateAttestation('ghost', { rfc3161Token: 'x' }, 'complete'))
          .rejects.toThrow('Evidence record "ghost" not found. Cannot update attestation.');
      });

      it('listByAttestationStatus returns exactly the records in that status', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'p-1', attestationStatus: 'pending' }));
        await adapter.store(makeEnvelope({ evidenceId: 'p-2', sequenceNumber: 2, attestationStatus: 'complete' }));
        await adapter.store(makeEnvelope({ evidenceId: 'p-3', sequenceNumber: 3, attestationStatus: 'pending' }));
        expect(ids(await adapter.listByAttestationStatus('pending')).sort()).toEqual(['p-1', 'p-3']);
        expect(ids(await adapter.listByAttestationStatus('none'))).toEqual([]);
      });

      // The retry pass reads the records it
      // can help, by the retry-obtainable component they are missing, never by
      // the status word: a record waiting for an anchor or a signature is
      // 'pending' too, and must not fill the page.
      describe('listByMissingObtainable', () => {
        const withToken = (token: string | null | undefined) => (env: EvidenceEnvelope): EvidenceEnvelope => {
          env.nonRepudiation = token === undefined ? {} : { rfc3161Token: token as string };
          return env;
        };

        it('lists pending records with no timestamp, oldest first, and takes a limit', async () => {
          await adapter.store(makeEnvelope({ evidenceId: 'm-mid', capturedAt: '2026-03-22T10:00:01.000Z', sequenceNumber: 1, attestationStatus: 'pending' }));
          await adapter.store(makeEnvelope({ evidenceId: 'm-old', capturedAt: '2026-03-22T10:00:00.000Z', sequenceNumber: 2, attestationStatus: 'pending' }));
          await adapter.store(makeEnvelope({ evidenceId: 'm-new', capturedAt: '2026-03-22T10:00:02.000Z', sequenceNumber: 3, attestationStatus: 'pending' }));

          expect(ids(await adapter.listByMissingObtainable(['timestamp']))).toEqual(['m-old', 'm-mid', 'm-new']);
          expect(ids(await adapter.listByMissingObtainable(['timestamp'], 2))).toEqual(['m-old', 'm-mid']);
          expect(ids(await adapter.listByMissingObtainable(['timestamp'], 99))).toEqual(['m-old', 'm-mid', 'm-new']);
          expect(ids(await adapter.listByMissingObtainable(['timestamp'], 0))).toEqual([]);
        });

        it('never lists a record that holds its timestamp, or one that is not pending', async () => {
          await adapter.store(withToken('tok')(makeEnvelope({ evidenceId: 'm-waits-anchor', sequenceNumber: 1, attestationStatus: 'pending' })));
          await adapter.store(makeEnvelope({ evidenceId: 'm-none', sequenceNumber: 2, attestationStatus: 'none' }));
          await adapter.store(makeEnvelope({ evidenceId: 'm-partial', sequenceNumber: 3, attestationStatus: 'partial' }));
          await adapter.store(makeEnvelope({ evidenceId: 'm-needs-ts', sequenceNumber: 4, attestationStatus: 'pending' }));

          expect(ids(await adapter.listByMissingObtainable(['timestamp']))).toEqual(['m-needs-ts']);
        });

        // Three rules agree on what a missing token is: the engine's status
        // rule (missingAttestationComponents), this query, and the fill rule
        // updateAttestation() applies. Absent, null and empty are all missing,
        // so an empty token is listed AND the retry's token replaces it.
        it('an empty or null token is listed, and updateAttestation() fills it', async () => {
          await adapter.store(withToken('')(makeEnvelope({ evidenceId: 'm-empty', sequenceNumber: 1, attestationStatus: 'pending' })));
          await adapter.store(withToken(null)(makeEnvelope({ evidenceId: 'm-null', sequenceNumber: 2, attestationStatus: 'pending', capturedAt: '2026-03-22T10:00:01.000Z' })));
          expect(ids(await adapter.listByMissingObtainable(['timestamp']))).toEqual(['m-empty', 'm-null']);

          await adapter.updateAttestation('m-empty', { rfc3161Token: 'tok-e' }, 'partial');
          await adapter.updateAttestation('m-null', { rfc3161Token: 'tok-n' }, 'partial');
          expect((await adapter.retrieve('m-empty'))!.nonRepudiation.rfc3161Token).toBe('tok-e');
          expect((await adapter.retrieve('m-null'))!.nonRepudiation.rfc3161Token).toBe('tok-n');
          expect(await adapter.listByMissingObtainable(['timestamp'])).toEqual([]);
        });

        it('an empty artifact from the caller fills nothing', async () => {
          await adapter.store(makeEnvelope({ evidenceId: 'm-no-fill', attestationStatus: 'pending' }));
          const before = await adapter.listEnvelopeRevisions('m-no-fill');
          await adapter.updateAttestation('m-no-fill', { rfc3161Token: '' }, 'pending');
          expect((await adapter.retrieve('m-no-fill'))!.nonRepudiation.rfc3161Token).toBeUndefined();
          expect(await adapter.listEnvelopeRevisions('m-no-fill')).toEqual(before);
        });

        it('400 older records waiting on what the retry cannot obtain do not fill the page', async () => {
          for (let i = 0; i < 400; i++) {
            const seconds = String(i % 60).padStart(2, '0');
            const minutes = String(Math.floor(i / 60)).padStart(2, '0');
            await adapter.store(withToken('tok')(makeEnvelope({
              evidenceId: `m-wait-${i}`,
              sequenceNumber: i + 1,
              capturedAt: `2026-03-22T09:${minutes}:${seconds}.000Z`,
              attestationStatus: 'pending',
            })));
          }
          await adapter.store(makeEnvelope({ evidenceId: 'm-late', sequenceNumber: 401, capturedAt: '2026-03-22T10:00:00.000Z', attestationStatus: 'pending' }));

          expect(ids(await adapter.listByAttestationStatus('pending', 100))).not.toContain('m-late');
          expect(ids(await adapter.listByMissingObtainable(['timestamp'], 100))).toEqual(['m-late']);
        }, 60_000);

        it('lists nothing for no components', async () => {
          await adapter.store(makeEnvelope({ evidenceId: 'm-1', attestationStatus: 'pending' }));
          expect(await adapter.listByMissingObtainable([])).toEqual([]);
        });

        it('refuses the anchor, and anything else the retry cannot obtain', async () => {
          for (const component of ['blockchain', 'anchor', 'webauthn', 'assertionTimestamp', '']) {
            await expect(
              adapter.listByMissingObtainable([component as 'timestamp']),
            ).rejects.toThrow(`listByMissingObtainable: '${component}' is not a retry-obtainable component`);
          }
        });

        it('refuses a limit that is not a non-negative integer', async () => {
          for (const bad of [-1, 1.5, Number.NaN, '2' as unknown as number]) {
            await expect(adapter.listByMissingObtainable(['timestamp'], bad)).rejects.toBeInstanceOf(InvalidPaginationError);
          }
        });
      });
    });

    // ── Recovery writes that mutate an envelope ───────────────────────────

    describe('recovery mutations', () => {
      it('updateEnvelopeChainLink rewrites only integrity.chainLink', async () => {
        const env = makeEnvelope({ evidenceId: 'cl-1', chainLink: 'old-link' });
        await adapter.store(env);
        await adapter.updateEnvelopeChainLink('cl-1', 'new-link');
        const got = (await adapter.retrieve('cl-1'))!;
        expect(got.integrity.chainLink).toBe('new-link');
        expect(got.integrity.canonicalDigest).toBe(env.integrity.canonicalDigest);
        expect(got.payload).toEqual(snapshot(env.payload));
      });

      it('appendCustodyEntry appends and never rewrites earlier entries', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'cu-1' }));
        await adapter.appendCustodyEntry('cu-1', {
          timestamp: '2026-04-04T12:00:00.000Z', actor: 'bob', action: 'reviewed', systemId: 'conformance-system',
        });
        const got = (await adapter.retrieve('cu-1'))!;
        expect(got.custodyChain.map((c) => c.action)).toEqual(['decision_captured', 'reviewed']);
      });

      it('updateEnvelopeChainLink and appendCustodyEntry on an unknown record throw the not-found message', async () => {
        await expect(adapter.updateEnvelopeChainLink('ghost', null))
          .rejects.toThrow('Evidence record "ghost" not found.');
        await expect(adapter.appendCustodyEntry('ghost', {
          timestamp: 't', actor: 'a', action: 'reviewed', systemId: 's',
        })).rejects.toThrow('Evidence record "ghost" not found.');
      });

      // ── Hashed, chained, ledgered custody appends ───────────────────────

      it('appendCustodyEntry mints entryHash / prevEntryHash and writes a matching custody_entries row', async () => {
        const env = makeEnvelope({ evidenceId: 'cu-2' });
        await adapter.store(env);
        await adapter.appendCustodyEntry('cu-2', {
          timestamp: '2026-04-04T12:00:00.000Z', actor: 'bob', action: 'reviewed', systemId: 'conformance-system',
          metadata: { b: 1, a: 'x' },
        }, { recoveryId: 'ann-1' });
        await adapter.appendCustodyEntry('cu-2', {
          timestamp: '2026-04-04T12:01:00.000Z', actor: 'carol', action: 'relinked', systemId: 'conformance-system',
        });
        const got = (await adapter.retrieve('cu-2'))!;
        const [captured, first, second] = got.custodyChain;
        expect(captured.entryHash).toBeUndefined();
        expect(first.entryHash).toMatch(/^[0-9a-f]{64}$/);
        expect(first.prevEntryHash).toBeNull();
        expect(second.prevEntryHash).toBe(first.entryHash);
        expect(first.entryHash).toBe(computeCustodyEntryHash({
          prevEntryHash: null, evidenceId: 'cu-2', canonicalDigest: env.integrity.canonicalDigest,
          action: 'reviewed', actor: 'bob', timestamp: '2026-04-04T12:00:00.000Z', systemId: 'conformance-system',
          metadata: { b: 1, a: 'x' },
        }));
        expect(verifyCustodyTrail(got)).toEqual({ valid: true, hashedEntries: 2, unhashedEntries: 1, failures: [] });

        const rows = await adapter.listCustodyEntries('cu-2');
        expect(rows.map((r) => r.entryHash)).toEqual([first.entryHash, second.entryHash]);
        expect(rows[0]).toEqual({
          id: rows[0].id, evidenceId: 'cu-2', chainId: 'default', canonicalDigest: env.integrity.canonicalDigest,
          action: 'reviewed', actor: 'bob', timestamp: '2026-04-04T12:00:00.000Z', systemId: 'conformance-system',
          metadata: { a: 'x', b: 1 }, prevEntryHash: null, entryHash: first.entryHash, recoveryId: 'ann-1',
        });
        expect(rows[1]).toMatchObject({ prevEntryHash: first.entryHash, recoveryId: null, metadata: null, action: 'relinked' });
        expect(typeof rows[0].id).toBe('number');
        expect(rows[1].id).toBeGreaterThan(rows[0].id);
        expect(await adapter.listCustodyEntries('ghost')).toEqual([]);
      });

      it('appendCustodyEntry replaces a caller-supplied entryHash / prevEntryHash with the ones it mints', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'cu-3' }));
        await adapter.appendCustodyEntry('cu-3', {
          timestamp: 't', actor: 'a', action: 'reviewed', systemId: 's',
          entryHash: 'f'.repeat(64), prevEntryHash: 'e'.repeat(64),
        });
        const [, minted] = (await adapter.retrieve('cu-3'))!.custodyChain;
        expect(minted.entryHash).not.toBe('f'.repeat(64));
        expect(minted.prevEntryHash).toBeNull();
        expect(verifyCustodyTrail((await adapter.retrieve('cu-3'))!).valid).toBe(true);
      });

      it('applyRelink commits the links, the record and the hashed entries together', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'ar-1', chainLink: 'bad', sequenceNumber: 1 }));
        await adapter.store(makeEnvelope({ evidenceId: 'ar-2', chainLink: 'bad', sequenceNumber: 2 }));
        const rlk = makeRelink({
          id: 'ar-rlk', fromSequence: 1, toSequence: 2,
          modifiedLinks: [
            { evidenceId: 'ar-1', sequenceNumber: 1, previousChainLink: 'bad', newChainLink: null },
            { evidenceId: 'ar-2', sequenceNumber: 2, previousChainLink: 'bad', newChainLink: 'good' },
          ],
        });
        const entry = { timestamp: 't', actor: 'admin', action: 'relinked' as const, systemId: 's', metadata: { relinkId: 'ar-rlk' } };
        await adapter.applyRelink(rlk, [{ evidenceId: 'ar-1', entry }, { evidenceId: 'ar-2', entry }, { evidenceId: 'ar-2', entry: { ...entry, action: 'reviewed' } }]);
        expect((await adapter.retrieve('ar-1'))!.integrity.chainLink).toBeNull();
        expect((await adapter.retrieve('ar-2'))!.integrity.chainLink).toBe('good');
        expect(await adapter.getRelink('ar-rlk')).toEqual(rlk);
        const one = await adapter.listCustodyEntries('ar-1');
        const two = await adapter.listCustodyEntries('ar-2');
        expect(one.map((r) => [r.action, r.prevEntryHash, r.recoveryId])).toEqual([['relinked', null, 'ar-rlk']]);
        // Two appends to one record inside one transaction chain to each other.
        expect(two.map((r) => [r.action, r.prevEntryHash])).toEqual([['relinked', null], ['reviewed', two[0].entryHash]]);
        expect(verifyCustodyTrail((await adapter.retrieve('ar-2'))!).valid).toBe(true);
      });

      it('applyRelink with an unknown record in the custody list leaves links, record and ledger untouched', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'ar-3', chainLink: 'bad' }));
        const rlk = makeRelink({
          id: 'ar-rlk-3',
          modifiedLinks: [{ evidenceId: 'ar-3', sequenceNumber: 1, previousChainLink: 'bad', newChainLink: 'good' }],
        });
        const entry = { timestamp: 't', actor: 'admin', action: 'relinked' as const, systemId: 's' };
        await expect(adapter.applyRelink(rlk, [{ evidenceId: 'ar-3', entry }, { evidenceId: 'ghost', entry }]))
          .rejects.toThrow('Evidence record "ghost" not found.');
        const got = (await adapter.retrieve('ar-3'))!;
        expect(got.integrity.chainLink).toBe('bad');
        expect(got.custodyChain).toHaveLength(1);
        expect(await adapter.getRelink('ar-rlk-3')).toBeNull();
        expect(await adapter.listCustodyEntries('ar-3')).toEqual([]);
      });

      it('applyRelink refuses a duplicate relink id and writes nothing', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'ar-4', chainLink: 'bad' }));
        await adapter.storeRelink(makeRelink({ id: 'ar-rlk-4' }));
        const rlk = makeRelink({
          id: 'ar-rlk-4',
          modifiedLinks: [{ evidenceId: 'ar-4', sequenceNumber: 1, previousChainLink: 'bad', newChainLink: 'good' }],
        });
        await expect(adapter.applyRelink(rlk, [{ evidenceId: 'ar-4', entry: { timestamp: 't', actor: 'a', action: 'relinked', systemId: 's' } }]))
          .rejects.toBeInstanceOf(DuplicateRecordError);
        expect((await adapter.retrieve('ar-4'))!.integrity.chainLink).toBe('bad');
        expect(await adapter.listCustodyEntries('ar-4')).toEqual([]);
      });

      it('listCustodyEntries returns detached copies', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'cu-5' }));
        await adapter.appendCustodyEntry('cu-5', { timestamp: 't', actor: 'a', action: 'reviewed', systemId: 's', metadata: { k: 'v' } });
        const a = await adapter.listCustodyEntries('cu-5');
        (a[0].metadata as Record<string, unknown>).k = 'changed';
        a[0].actor = 'changed';
        const b = await adapter.listCustodyEntries('cu-5');
        expect(b[0].actor).toBe('a');
        expect(b[0].metadata).toEqual({ k: 'v' });
      });
    });

    // ── The append-only revision log ───────────────────────────────
    //
    // Three adapters have to agree on when a revision row is written, what it
    // says and what an absent one means, because "was this record rewritten
    // after capture" must not change with the backend. It is the only finding
    // in the store that is an answer about HISTORY rather than present state,
    // and it is what tells a rewrite-and-reseat from an honest broken link.

    describe('revision log', () => {
      it('store() writes revision 0 with the capture digest, the link and the capturing actor', async () => {
        const envelope = makeEnvelope({ evidenceId: 'rv-1', chainLink: 'link-1' });
        await adapter.store(envelope, 'default');
        const revisions = await adapter.listEnvelopeRevisions('rv-1');
        expect(revisions).toHaveLength(1);
        expect(revisions[0]).toMatchObject({
          evidenceId: 'rv-1',
          revisionNo: 0,
          canonicalDigest: envelope.integrity.canonicalDigest,
          chainLink: 'link-1',
          cause: 'capture',
          actor: envelope.custodyChain[0].actor,
        });
        expect(revisions[0].recordedAt).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);
      });

      it('a genesis record records a NULL chain link, not the string "null"', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'rv-2', chainLink: null }), 'default');
        expect((await adapter.listEnvelopeRevisions('rv-2'))[0].chainLink).toBeNull();
      });

      it('getCaptureDigests maps the ids it has revision 0 for and OMITS the rest', async () => {
        const one = makeEnvelope({ evidenceId: 'rv-3' });
        await adapter.store(one, 'default');
        const digests = await adapter.getCaptureDigests(['rv-3', 'rv-never-stored']);
        expect(digests['rv-3']).toBe(one.integrity.canonicalDigest);
        // Absent, not null: an id with no capture revision is one the store
        // cannot speak for. Mapping it to null would make "unprovable" look
        // like an answer, and a verifier reading it as "clean" is exactly the
        // silence a pre-0.3.16 record already provides.
        expect('rv-never-stored' in digests).toBe(false);
        expect(await adapter.getCaptureDigests([])).toEqual({});
      });

      it('updateAttestation appends an attestation_retry revision carrying the digest UNCHANGED', async () => {
        const envelope = makeEnvelope({ evidenceId: 'rv-4', chainLink: 'link-4' });
        await adapter.store(envelope, 'default');
        await adapter.updateAttestation('rv-4', { rfc3161Token: 'dG9rZW4=' }, 'complete');
        const revisions = await adapter.listEnvelopeRevisions('rv-4');
        expect(revisions.map((r) => [r.revisionNo, r.cause])).toEqual([[0, 'capture'], [1, 'attestation_retry']]);
        expect(revisions[1].actor).toBe('tzun-attestation');
        // The one permitted mutation touches neither payload nor integrity,
        // so the row proves the retry superseded nothing.
        expect(revisions[1].canonicalDigest).toBe(envelope.integrity.canonicalDigest);
        expect(revisions[1].chainLink).toBe('link-4');
      });

      it('updateEnvelopeChainLink appends a relink revision with the NEW link and the same digest', async () => {
        const envelope = makeEnvelope({ evidenceId: 'rv-5', chainLink: 'broken' });
        await adapter.store(envelope, 'default');
        await adapter.updateEnvelopeChainLink('rv-5', 'repaired');
        const revisions = await adapter.listEnvelopeRevisions('rv-5');
        expect(revisions.map((r) => [r.revisionNo, r.cause])).toEqual([[0, 'capture'], [1, 'relink']]);
        expect(revisions[1].chainLink).toBe('repaired');
        expect(revisions[1].canonicalDigest).toBe(envelope.integrity.canonicalDigest);
        expect(revisions[1].actor).toBe('tzun-recovery');
      });

      it('applyRelink attributes the revision to the operator who authorised it, in the same transaction', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'rv-6', sequenceNumber: 1, chainLink: 'broken' }), 'default');
        const relink = makeRelink({
          id: 'rv-relink-1',
          modifiedLinks: [
            { evidenceId: 'rv-6', sequenceNumber: 1, previousChainLink: 'broken', newChainLink: 'repaired' },
          ],
        });
        relink.relinkedBy = 'operator@acme.example';
        await adapter.applyRelink(relink, [
          { evidenceId: 'rv-6', entry: { timestamp: relink.relinkedAt, actor: relink.relinkedBy, action: 'relinked', systemId: 'tzun-recovery' } },
        ]);
        const revisions = await adapter.listEnvelopeRevisions('rv-6');
        expect(revisions.map((r) => r.cause)).toEqual(['capture', 'relink']);
        expect(revisions[1].actor).toBe('operator@acme.example');
        expect(revisions[1].chainLink).toBe('repaired');
      });

      it('a relink on a record with NO capture revision starts at revision 1, never backfilling 0', async () => {
        // The migration case: a record written by an SDK older than 0.3.16.
        // Writing today's digest as "the digest this was captured with" would
        // launder an already-rewritten legacy record, so revision 0 stays
        // absent and getCaptureDigests keeps answering "unprovable".
        await adapter.store(makeEnvelope({ evidenceId: 'rv-7', chainLink: 'broken' }), 'default');
        await deleteRevisionRowsForTest(adapter, 'rv-7');
        expect(await adapter.listEnvelopeRevisions('rv-7')).toEqual([]);

        await adapter.updateEnvelopeChainLink('rv-7', 'repaired');
        const revisions = await adapter.listEnvelopeRevisions('rv-7');
        expect(revisions.map((r) => [r.revisionNo, r.cause])).toEqual([[1, 'relink']]);
        expect('rv-7' in (await adapter.getCaptureDigests(['rv-7']))).toBe(false);
      });

      it('listEnvelopeRevisions returns detached copies and is empty for an unknown record', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'rv-8' }), 'default');
        const a = await adapter.listEnvelopeRevisions('rv-8');
        a[0].canonicalDigest = 'changed';
        expect((await adapter.listEnvelopeRevisions('rv-8'))[0].canonicalDigest).not.toBe('changed');
        expect(await adapter.listEnvelopeRevisions('rv-nope')).toEqual([]);
      });
    });

    // ── Idempotency keys ───────────────────────────────────
    //
    // The replay contract shared with the platform: same key + same caller
    // input replays the original receipt, same key + different input is a
    // conflict, and the claim is atomic with the write. The fingerprint is
    // the caller's, over caller input only — so a retry arrives as a NEW
    // envelope (fresh evidenceId, capturedAt, sequence) with the SAME
    // fingerprint, which is exactly what these cases send.

    describe('idempotency keys', () => {
      const claim = (key: string, fingerprint = 'fp-a') => ({ idempotency: { key, fingerprint } });

      it('a free key is claimed: the record is stored and the receipt describes it', async () => {
        const env = makeEnvelope({ evidenceId: 'idem-1', sequenceNumber: 1 });
        const outcome = await adapter.storeIdempotent(env, 'chain-i', claim('key-1'));
        expect(outcome).toEqual({
          kind: 'claimed',
          receipt: {
            evidenceId: 'idem-1',
            chainId: 'chain-i',
            sequenceNumber: 1,
            canonicalDigest: env.integrity.canonicalDigest,
          },
        });
        expect(await adapter.retrieve('idem-1')).toEqual(snapshot(env));
      });

      it('the receipt names the default chain when none was given', async () => {
        const outcome = await adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-d' }), undefined, claim('key-d'));
        expect(outcome).toMatchObject({ kind: 'claimed', receipt: { chainId: 'default' } });
        expect(await adapter.getChainForRecord('idem-d')).toBe('default');
      });

      it('the same key and fingerprint replays the original receipt and stores nothing, after the head has moved', async () => {
        const first = makeEnvelope({ evidenceId: 'idem-orig', sequenceNumber: 1 });
        const claimed = await adapter.storeIdempotent(first, undefined, claim('key-r'));
        await adapter.store(makeEnvelope({ evidenceId: 'idem-other', sequenceNumber: 2 }));

        // The retry: a new envelope built at the new head, the same key, the same input.
        const retry = makeEnvelope({ evidenceId: 'idem-retry', sequenceNumber: 3, capturedAt: '2026-03-22T10:05:00.000Z' });
        const outcome = await adapter.storeIdempotent(retry, undefined, {
          ...claim('key-r'),
          expectChainHead: { sequence: 2, digest: (await adapter.getLastDigest())! },
        });

        expect(outcome).toEqual({ kind: 'replay', receipt: (claimed as { receipt: unknown }).receipt });
        expect(await adapter.retrieve('idem-retry')).toBeNull();
        expect(await adapter.getChainLength()).toBe(2);
        expect(await adapter.getLastSequence()).toBe(2);
      });

      it('the same key with a different fingerprint is a conflict and stores nothing', async () => {
        await adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-c1' }), undefined, claim('key-c', 'fp-a'));
        const outcome = await adapter.storeIdempotent(
          makeEnvelope({ evidenceId: 'idem-c2', sequenceNumber: 2 }),
          undefined,
          claim('key-c', 'fp-b'),
        );
        expect(outcome).toEqual({ kind: 'conflict' });
        expect(await adapter.retrieve('idem-c2')).toBeNull();
        expect(await adapter.getChainLength()).toBe(1);
      });

      it('different keys are independent', async () => {
        const a = await adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-k1' }), undefined, claim('key-x'));
        const b = await adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-k2', sequenceNumber: 2 }), undefined, claim('key-y'));
        expect([a.kind, b.kind]).toEqual(['claimed', 'claimed']);
        expect(await adapter.getChainLength()).toBe(2);
      });

      it('a refused store does not consume the key: a stale head throws, and the corrected retry claims it', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'idem-h1', digest: '11'.repeat(32) }));
        const stale = adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-h2', sequenceNumber: 2 }), undefined, {
          ...claim('key-h'),
          expectChainHead: { sequence: 0, digest: null },
        });
        await expect(stale).rejects.toThrow(ChainConflictError);
        expect(await adapter.retrieve('idem-h2')).toBeNull();

        const corrected = await adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-h2', sequenceNumber: 2 }), undefined, {
          ...claim('key-h'),
          expectChainHead: { sequence: 1, digest: '11'.repeat(32) },
        });
        expect(corrected).toMatchObject({ kind: 'claimed', receipt: { evidenceId: 'idem-h2' } });
      });

      it('a sealed chain refuses the first attempt without consuming the key, and a claimed key still replays after the seal', async () => {
        await adapter.storeChain(makeChain({ chainId: 'idem-sealed' }));
        const claimed = await adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-s1' }), 'idem-sealed', claim('key-s1'));
        await adapter.sealChain('idem-sealed', '2026-04-04T11:00:00.000Z');

        // Claimed before the seal: the retry replays; the seal is not consulted.
        const retry = await adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-s1-retry', sequenceNumber: 2 }), 'idem-sealed', claim('key-s1'));
        expect(retry).toEqual({ kind: 'replay', receipt: (claimed as { receipt: unknown }).receipt });

        // Never claimed: the store's own refusal, and the key stays free.
        await expect(
          adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-s2', sequenceNumber: 2 }), 'idem-sealed', claim('key-s2')),
        ).rejects.toBeInstanceOf(ChainSealedError);
        const elsewhere = await adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-s2', sequenceNumber: 1 }), 'idem-open', claim('key-s2'));
        expect(elsewhere).toMatchObject({ kind: 'claimed', receipt: { chainId: 'idem-open' } });
      });

      it('two concurrent calls with one key store exactly one record', async () => {
        const outcomes = await Promise.all([
          adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-race-a' }), undefined, {
            ...claim('key-race'), expectChainHead: { sequence: 0, digest: null },
          }),
          adapter.storeIdempotent(makeEnvelope({ evidenceId: 'idem-race-b' }), undefined, {
            ...claim('key-race'), expectChainHead: { sequence: 0, digest: null },
          }),
        ]);
        expect(outcomes.map((o) => o.kind).sort()).toEqual(['claimed', 'replay']);
        const [x, y] = outcomes as Array<{ receipt: unknown }>;
        expect(x.receipt).toEqual(y.receipt);
        expect(await adapter.getChainLength()).toBe(1);
      });
    });

    // ── Chain identities ──────────────────────────────────────────────────

    describe('chain identities', () => {
      it('storeChain then getChain round-trips, with optional fields absent when not set', async () => {
        await adapter.storeChain(makeChain({ chainId: 'ci-1' }));
        expect(await adapter.getChain('ci-1')).toEqual({
          chainId: 'ci-1', status: 'active', createdAt: '2026-04-04T10:00:00.000Z',
        });
        expect(await adapter.getChain('ci-missing')).toBeNull();
      });

      it('createdAt and sealedAt come back as ISO-8601 strings', async () => {
        await adapter.storeChain(makeChain({ chainId: 'ts-1' }));
        await adapter.sealChain('ts-1', '2026-04-04T11:00:00.000Z');
        const got = (await adapter.getChain('ts-1'))!;
        expect(got.status).toBe('sealed');
        expect(got.createdAt).toBe('2026-04-04T10:00:00.000Z');
        expect(got.sealedAt).toBe('2026-04-04T11:00:00.000Z');
      });

      // A seal is final: the SQL adapters' `chains` triggers
      // refuse to lift or re-date one, so a second sealChain() is a no-op that
      // keeps the first sealedAt, on every backend (as on the platform).
      it('sealing a sealed chain keeps its first sealedAt', async () => {
        await adapter.storeChain(makeChain({ chainId: 'reseal-1' }));
        await adapter.sealChain('reseal-1', '2026-04-04T11:00:00.000Z');
        await expect(adapter.sealChain('reseal-1', '2026-04-05T09:30:00.000Z')).resolves.toBeUndefined();
        const got = (await adapter.getChain('reseal-1'))!;
        expect(got.status).toBe('sealed');
        expect(got.sealedAt).toBe('2026-04-04T11:00:00.000Z');
      });

      it('sealChain on an unknown chain throws the not-found message', async () => {
        await expect(adapter.sealChain('ghost', '2026-04-04T11:00:00.000Z'))
          .rejects.toThrow('Chain "ghost" not found.');
      });

      // Status decides, never recency. Two open chains give no safe guess and
      // an all-sealed store has no chain to append to, so both are typed
      // refusals: naming the newest row would pick between open chains by
      // age, or name a sealed one.
      it('getActiveChainId: default until something is written, the lone open chain, and typed refusals otherwise', async () => {
        expect(await adapter.getActiveChainId()).toBe('default');
        await adapter.storeChain(makeChain({ chainId: 'old', createdAt: '2026-04-01T00:00:00.000Z' }));
        expect(await adapter.getActiveChainId()).toBe('old');

        await adapter.storeChain(makeChain({ chainId: 'new', createdAt: '2026-04-02T00:00:00.000Z' }));
        await expect(adapter.getActiveChainId()).rejects.toBeInstanceOf(AmbiguousActiveChainError);
        await expect(adapter.getActiveChainId()).rejects.toMatchObject({
          code: 'ambiguous_active_chain',
          activeChainIds: ['old', 'new'],
          implicitChainIds: [],
        });

        // Status decides, not recency: sealing the NEWER row leaves the older one.
        await adapter.sealChain('new', '2026-04-03T00:00:00.000Z');
        expect(await adapter.getActiveChainId()).toBe('old');

        await adapter.sealChain('old', '2026-04-04T00:00:00.000Z');
        await expect(adapter.getActiveChainId()).rejects.toBeInstanceOf(NoActiveChainError);
        const refusal = await adapter.getActiveChainId().then(
          (id) => { throw new Error(`resolved to "${id}" on an all-sealed store`); },
          (e: unknown) => e as NoActiveChainError,
        );
        expect(refusal.code).toBe('no_active_chain');
        expect(refusal.chains.map((c) => `${c.chainId}:${c.status}`)).toEqual(['old:sealed', 'new:sealed']);
      });

      it('a chain with records and no identity row is open, and counts against a lone active row', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'implicit-default', sequenceNumber: 1 }));
        expect(await adapter.getActiveChainId()).toBe('default');

        await adapter.storeChain(makeChain({ chainId: 'tenant-globex' }));
        await expect(adapter.getActiveChainId()).rejects.toMatchObject({
          code: 'ambiguous_active_chain',
          activeChainIds: ['tenant-globex', 'default'],
          implicitChainIds: ['default'],
        });

        // Materialise and seal the implicit chain: the row is now the lone open chain.
        await adapter.storeChain(makeChain({ chainId: 'default', status: 'sealed', sealedAt: '2026-04-04T11:00:00.000Z' }));
        expect(await adapter.getActiveChainId()).toBe('tenant-globex');
      });

      it('listRecordChainIds is every chain a record belongs to, sorted, with or without an identity row', async () => {
        expect(await adapter.listRecordChainIds()).toEqual([]);
        await adapter.store(makeEnvelope({ evidenceId: 'r-1', sequenceNumber: 1 }));
        await adapter.store(makeEnvelope({ evidenceId: 'r-2', sequenceNumber: 1 }), 'zeta');
        await adapter.store(makeEnvelope({ evidenceId: 'r-3', sequenceNumber: 1 }), 'alpha');
        await adapter.store(makeEnvelope({ evidenceId: 'r-4', sequenceNumber: 2 }), 'zeta');
        await adapter.storeChain(makeChain({ chainId: 'row-without-records' }));
        expect(await adapter.listRecordChainIds()).toEqual(['alpha', 'default', 'zeta']);
      });
    });

    // ── Recovery ledger round trips ───────────────────────────────────────

    describe('recovery ledger', () => {
      it('annotation, relink and fork records round-trip with ISO-8601 timestamps', async () => {
        const ann = makeAnnotation({ id: 'ann-rt' });
        const rlk = makeRelink({ id: 'rlk-rt' });
        const frk = makeFork({ id: 'frk-rt' });
        await adapter.storeAnnotation(ann);
        await adapter.storeRelink(rlk);
        await adapter.storeFork(frk);
        expect(await adapter.getAnnotation('ann-rt')).toEqual(snapshot(ann));
        expect(await adapter.getRelink('rlk-rt')).toEqual(snapshot(rlk));
        expect(await adapter.getFork('frk-rt')).toEqual(snapshot(frk));
        expect(await adapter.getAnnotation('ghost')).toBeNull();
        expect(await adapter.getRelink('ghost')).toBeNull();
        expect(await adapter.getFork('ghost')).toBeNull();
      });

      it('listAnnotationsForRecord matches on membership of affectedRecords', async () => {
        await adapter.storeAnnotation(makeAnnotation({ id: 'a-1', affectedRecords: ['ev-1', 'ev-2'] }));
        await adapter.storeAnnotation(makeAnnotation({ id: 'a-2', affectedRecords: ['ev-3'] }));
        expect((await adapter.listAnnotationsForRecord('ev-2')).map((a) => a.id)).toEqual(['a-1']);
        expect((await adapter.listAnnotationsForRecord('ev-9')).map((a) => a.id)).toEqual([]);
      });

      it('listForksForChain matches a chain on either side of the fork', async () => {
        await adapter.storeFork(makeFork({ id: 'f-1', oldChainId: 'x', newChainId: 'y' }));
        await adapter.storeFork(makeFork({ id: 'f-2', oldChainId: 'y', newChainId: 'z' }));
        expect((await adapter.listForksForChain('y')).map((f) => f.id).sort()).toEqual(['f-1', 'f-2']);
        expect((await adapter.listForksForChain('z')).map((f) => f.id)).toEqual(['f-2']);
      });
    });

    // ── Tamper incidents ──────────────────────────────────────────────────

    describe('incidents', () => {
      it('storeIncident then getIncident round-trips, detectedAt as an ISO-8601 string', async () => {
        const inc = makeIncident({ id: 'i-rt', affectedSequenceRange: { from: 1, to: 2 } });
        await adapter.storeIncident(inc);
        expect(await adapter.getIncident('i-rt')).toEqual(snapshot(inc));
        expect(await adapter.getIncident('ghost')).toBeNull();
      });

      it('a duplicate incident id is refused', async () => {
        await adapter.storeIncident(makeIncident({ id: 'i-dup' }));
        const attempt = adapter.storeIncident(makeIncident({ id: 'i-dup', details: 'second write' }));
        await expect(attempt).rejects.toThrow('Tamper incident "i-dup" already exists.');
        await expect(attempt).rejects.toThrow(DuplicateRecordError);
        expect((await adapter.getIncident('i-dup'))!.details).toBe('Digest mismatch detected on ev-001');
      });

      it('listIncidents filters by status and by severity', async () => {
        await adapter.storeIncident(makeIncident({ id: 'i-1', status: 'open', severity: 'critical' }));
        await adapter.storeIncident(makeIncident({ id: 'i-2', status: 'acknowledged', severity: 'warning' }));
        await adapter.storeIncident(makeIncident({ id: 'i-3', status: 'open', severity: 'warning' }));
        expect((await adapter.listIncidents({ status: 'open' })).map((i) => i.id).sort()).toEqual(['i-1', 'i-3']);
        expect((await adapter.listIncidents({ severity: 'warning' })).map((i) => i.id).sort()).toEqual(['i-2', 'i-3']);
        expect((await adapter.listIncidents({ status: 'open', severity: 'warning' })).map((i) => i.id)).toEqual(['i-3']);
      });

      it('updateIncidentStatus on an unknown incident throws the not-found message', async () => {
        await expect(adapter.updateIncidentStatus('ghost', 'acknowledged'))
          .rejects.toThrow('Tamper incident "ghost" not found. Cannot update status.');
      });

      it('resolving stamps resolvedAt and records resolvedBy / resolutionNotes', async () => {
        await adapter.storeIncident(makeIncident({ id: 'i-res' }));
        await adapter.updateIncidentStatus('i-res', 'resolved', { resolvedBy: 'alice', resolutionNotes: 'fixed' });
        const got = (await adapter.getIncident('i-res'))!;
        expect(got.status).toBe('resolved');
        expect(got.resolvedBy).toBe('alice');
        expect(got.resolutionNotes).toBe('fixed');
        expect(new Date(got.resolvedAt!).toISOString()).toBe(got.resolvedAt);
      });

      // The resolution metadata on a tamper incident is audit evidence:
      // who signed off that a detected integrity break was investigated, and
      // what they said. A second resolve with no metadata — an idempotent
      // retry, an ops-console double-submit (the operator console's resolve
      // button posts an empty body), a replayed webhook — keeps the resolver's
      // name and notes and the first resolvedAt. Writing null over them would
      // erase that sign-off silently.

      it('re-resolving without metadata preserves resolvedBy, resolutionNotes and the original resolvedAt', async () => {
        await adapter.storeIncident(makeIncident({ id: 'i-re' }));
        await adapter.updateIncidentStatus('i-re', 'resolved', { resolvedBy: 'alice', resolutionNotes: 'fixed' });
        const first = (await adapter.getIncident('i-re'))!;
        await new Promise((r) => setTimeout(r, 5));
        await adapter.updateIncidentStatus('i-re', 'resolved');
        const again = (await adapter.getIncident('i-re'))!;
        expect(again.status).toBe('resolved');
        expect(again.resolvedBy).toBe('alice');
        expect(again.resolutionNotes).toBe('fixed');
        expect(again.resolvedAt).toBe(first.resolvedAt);
      });

      it('re-resolving with new metadata replaces only the fields supplied', async () => {
        await adapter.storeIncident(makeIncident({ id: 'i-re2' }));
        await adapter.updateIncidentStatus('i-re2', 'resolved', { resolvedBy: 'alice', resolutionNotes: 'fixed' });
        const first = (await adapter.getIncident('i-re2'))!;
        await adapter.updateIncidentStatus('i-re2', 'resolved', { resolutionNotes: 'fixed, and root-caused' });
        const again = (await adapter.getIncident('i-re2'))!;
        expect(again.resolvedBy).toBe('alice');
        expect(again.resolutionNotes).toBe('fixed, and root-caused');
        expect(again.resolvedAt).toBe(first.resolvedAt);
      });

      it('transitioning away from resolved changes the status only', async () => {
        await adapter.storeIncident(makeIncident({ id: 'i-back' }));
        await adapter.updateIncidentStatus('i-back', 'resolved', { resolvedBy: 'alice', resolutionNotes: 'fixed' });
        await adapter.updateIncidentStatus('i-back', 'acknowledged');
        const got = (await adapter.getIncident('i-back'))!;
        expect(got.status).toBe('acknowledged');
        // What every adapter does today, asserted so it cannot drift silently;
        // whether reopening SHOULD clear them is the it.failing below.
        expect(got.resolvedBy).toBe('alice');
        expect(got.resolutionNotes).toBe('fixed');
        expect(got.resolvedAt).toBeDefined();
      });

      // Design decision not settled by Postgres-as-reference (all three keep
      // the stale resolver on reopen; the platform's own incident table clears
      // resolved_at/resolved_by_sub on undo). Marked it.failing so that the
      // day an adapter starts clearing, CI says so and the case
      // above has to be inverted with it.
      it.failing('reopening a resolved incident clears its resolution fields (reopen semantics undecided; adapters keep them, the platform undo clears them)', async () => {
        await adapter.storeIncident(makeIncident({ id: 'i-reopen' }));
        await adapter.updateIncidentStatus('i-reopen', 'resolved', { resolvedBy: 'alice', resolutionNotes: 'fixed' });
        await adapter.updateIncidentStatus('i-reopen', 'open');
        const got = (await adapter.getIncident('i-reopen'))!;
        expect(got.resolvedBy).toBeUndefined();
        expect(got.resolutionNotes).toBeUndefined();
        expect(got.resolvedAt).toBeUndefined();
      });
    });

    // ── AI-BOM catalog ────────────────────────────────────────────────────

    describe('catalog', () => {
      it('registerModelDescriptor is idempotent on identical canonical bytes', async () => {
        const first = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        const second = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        expect(first.alreadyExisted).toBe(false);
        expect(second).toEqual({ digest: first.digest, alreadyExisted: true });
        expect(await adapter.getModelDescriptor('sha256:nope')).toBeNull();
      });

      it('getModelDescriptor returns the exact canonical bytes that were hashed, firstRegisteredAt as ISO-8601', async () => {
        const { digest } = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 'tester');
        const row = (await adapter.getModelDescriptor(digest))!;
        expect(row.modelDescriptorDigest).toBe(digest);
        expect(row.firstRegisteredBy).toBe('tester');
        expect(row.source).toBe('manual');
        expect(new Date(row.firstRegisteredAt).toISOString()).toBe(row.firstRegisteredAt);
        const { createHash } = await import('node:crypto');
        expect('sha256:' + createHash('sha256').update(row.canonicalBytes).digest('hex')).toBe(digest);
      });

      it('listDescendantDescriptors returns the direct children of a parent digest', async () => {
        const parent = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        await adapter.registerModelDescriptor(
          makeDescriptor({ modelName: 'child', parentModelDescriptorDigest: parent.digest }), 'manual', 't',
        );
        const kids = await adapter.listDescendantDescriptors(parent.digest);
        expect(kids.map((k) => k.descriptor.modelName)).toEqual(['child']);
      });

      it('the enriched view applies annotations on top of the canonical descriptor', async () => {
        const { digest } = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        await adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(digest, {
          annotationId: 'lic', annotationType: 'set-license', valueJson: JSON.stringify({ license: 'apache-2.0' }),
        }));
        expect((await adapter.getEnrichedModelDescriptor(digest))!.license).toBe('apache-2.0');
        expect((await adapter.getModelDescriptor(digest))!.descriptor.license).toBeNull();
        expect(await adapter.getEnrichedModelDescriptor('sha256:nope')).toBeNull();
      });

      it('resolveModelDescriptorAlias is null for an unbound slug and the latest setAt otherwise', async () => {
        expect(await adapter.resolveModelDescriptorAlias('nope')).toBeNull();
        const a = await adapter.registerModelDescriptor(makeDescriptor({ modelVersion: '1' }), 'manual', 't');
        const b = await adapter.registerModelDescriptor(makeDescriptor({ modelVersion: '2' }), 'manual', 't');
        await adapter.setModelDescriptorAlias('current', a.digest, 'admin');
        await new Promise((r) => setTimeout(r, 5));
        await adapter.setModelDescriptorAlias('current', b.digest, 'admin');
        expect(await adapter.resolveModelDescriptorAlias('current')).toBe(b.digest);
      });
    });


    // ── Reference isolation ────────────────────────────────────────
    //
    // A real store serialises on write and parses on read, so nothing a caller
    // holds is the row, and every adapter behaves the same way. An adapter
    // that handed out live references into its own storage would let a
    // property assignment on what retrieve() returned rewrite stored evidence,
    // let VerifyingStorageProxy verify a digest and then return a writable
    // pointer to the verified object, and let a tamper "work" on that adapter
    // and do nothing on SQLite. Every read and every write path is asserted
    // here.

    describe('reference isolation', () => {
      it('an undefined-valued key is dropped on retrieve', async () => {
        const env = makeEnvelope({ evidenceId: 'u-1', aiOutput: { keep: 1, gone: undefined as unknown as string } });
        await adapter.store(env);
        const got = (await adapter.retrieve('u-1'))!;
        expect(Object.prototype.hasOwnProperty.call(got.payload.aiOutput, 'gone')).toBe(false);
        expect(got.payload.aiOutput).toEqual({ keep: 1 });
      });

      it('negative zero is stored as zero', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'z-1', aiOutput: { negz: -0, big: 1e21, tiny: 1e-7 } }));
        const got = (await adapter.retrieve('z-1'))!;
        expect(Object.is(got.payload.aiOutput.negz, 0)).toBe(true);
        expect(got.payload.aiOutput.big).toBe(1e21);
        expect(got.payload.aiOutput.tiny).toBe(1e-7);
      });

      it('retrieve returns a detached copy: mutating it does not change the store', async () => {
        const env = makeEnvelope({ evidenceId: 'iso-1' });
        // Snapshot BEFORE anything is mutated: an adapter that aliases the
        // fixture would otherwise move the expectation along with the tamper.
        const expected = snapshot(env);
        await adapter.store(env);
        const first = (await adapter.retrieve('iso-1'))!;
        first.payload.reason = 'TAMPERED';
        first.integrity.canonicalDigest = 'd'.repeat(64);
        first.custodyChain.push({ timestamp: 't', actor: 'x', action: 'reviewed', systemId: 's' });
        (first.payload.aiOutput as Record<string, unknown>).injected = true;
        expect(await adapter.retrieve('iso-1')).toEqual(expected);
      });

      it('two retrieve calls return distinct objects', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'iso-2' }));
        const a = await adapter.retrieve('iso-2');
        const b = await adapter.retrieve('iso-2');
        expect(a).toEqual(b);
        expect(a).not.toBe(b);
        expect(a!.payload).not.toBe(b!.payload);
      });

      it("store keeps no reference to the caller's object", async () => {
        const env = makeEnvelope({ evidenceId: 'iso-3' });
        const expected = snapshot(env);
        await adapter.store(env);
        env.payload.reason = 'CHANGED AFTER STORE';
        env.custodyChain.push({ timestamp: 't', actor: 'x', action: 'reviewed', systemId: 's' });
        expect(await adapter.retrieve('iso-3')).toEqual(expected);
      });

      it('list, listBySequence, getBySequenceRange, listByAttestationStatus, listByMissingObtainable and head return detached copies', async () => {
        const env = makeEnvelope({ evidenceId: 'iso-4', attestationStatus: 'pending' });
        const expected = snapshot(env);
        await adapter.store(env);
        const reads: Array<() => Promise<EvidenceEnvelope[]>> = [
          () => adapter.list(),
          () => adapter.listBySequence(),
          () => adapter.getBySequenceRange(1, 1),
          () => adapter.listByAttestationStatus('pending'),
          () => adapter.listByMissingObtainable(['timestamp']),
          async () => [(await adapter.head())!],
        ];
        for (const read of reads) {
          const [got] = await read();
          got.payload.reason = 'TAMPERED';
          got.custodyChain.length = 0;
        }
        expect(await adapter.retrieve('iso-4')).toEqual(expected);
      });

      it('updateAttestation is not visible through a previously retrieved envelope', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'iso-5' }));
        const held = (await adapter.retrieve('iso-5'))!;
        await adapter.updateAttestation('iso-5', { rfc3161Token: 'tok' }, 'complete');
        expect(held.attestationStatus).toBe('none');
        expect(held.nonRepudiation.rfc3161Token).toBeUndefined();
        expect((await adapter.retrieve('iso-5'))!.attestationStatus).toBe('complete');
      });

      it('getIncident and listIncidents return detached copies, nested arrays included', async () => {
        const inc = makeIncident({ id: 'iso-inc', affectedRecords: ['a'], affectedSequenceRange: { from: 1, to: 1 } });
        const expected = snapshot(inc);
        await adapter.storeIncident(inc);
        const got = (await adapter.getIncident('iso-inc'))!;
        got.affectedRecords.push('injected');
        got.affectedSequenceRange!.to = 99;
        got.status = 'resolved';
        const [listed] = await adapter.listIncidents();
        listed.affectedRecords.push('injected-via-list');
        expect(await adapter.getIncident('iso-inc')).toEqual(expected);
      });

      it("storeIncident keeps no reference to the caller's nested arrays", async () => {
        const inc = makeIncident({ id: 'iso-inc2', affectedRecords: ['a'] });
        const expected = snapshot(inc);
        await adapter.storeIncident(inc);
        inc.affectedRecords.push('added-after-store');
        expect(await adapter.getIncident('iso-inc2')).toEqual(expected);
      });

      it('chain, annotation, relink and fork reads return detached copies', async () => {
        const chain = makeChain({ chainId: 'iso-c' });
        const ann = makeAnnotation({ id: 'iso-a', affectedRecords: ['ev-1'] });
        const rlk = makeRelink({ id: 'iso-r' });
        const frk = makeFork({ id: 'iso-f' });
        const expected = { chain: snapshot(chain), ann: snapshot(ann), rlk: snapshot(rlk), frk: snapshot(frk) };
        await adapter.storeChain(chain);
        await adapter.storeAnnotation(ann);
        await adapter.storeRelink(rlk);
        await adapter.storeFork(frk);
        (await adapter.getChain('iso-c'))!.status = 'sealed';
        (await adapter.getAnnotation('iso-a'))!.affectedRecords.push('x');
        (await adapter.getAnnotation('iso-a'))!.originalDigests['ev-1'] = 'sha256:tampered';
        (await adapter.getRelink('iso-r'))!.modifiedLinks[0].newChainLink = 'tampered';
        (await adapter.getFork('iso-f'))!.sealedOldChainLength = 999;
        (await adapter.listChains())[0].status = 'sealed';
        (await adapter.listAnnotations('inc-001'))[0].affectedRecords.push('y');
        (await adapter.listRelinks('inc-001'))[0].modifiedLinks.length = 0;
        (await adapter.listForks('inc-001'))[0].reason = 'tampered';
        expect(await adapter.getChain('iso-c')).toEqual(expected.chain);
        expect(await adapter.getAnnotation('iso-a')).toEqual(expected.ann);
        expect(await adapter.getRelink('iso-r')).toEqual(expected.rlk);
        expect(await adapter.getFork('iso-f')).toEqual(expected.frk);
      });

      it("storeAnnotation and storeRelink keep no reference to the caller's nested values", async () => {
        const ann = makeAnnotation({ id: 'iso-a2', affectedRecords: ['ev-1'] });
        const rlk = makeRelink({ id: 'iso-r2' });
        const expectedAnn = snapshot(ann);
        const expectedRlk = snapshot(rlk);
        await adapter.storeAnnotation(ann);
        await adapter.storeRelink(rlk);
        ann.affectedRecords.push('later');
        ann.originalDigests['ev-9'] = 'sha256:later';
        rlk.modifiedLinks.push({ evidenceId: 'ev-9', sequenceNumber: 9, previousChainLink: null, newChainLink: 'l' });
        expect(await adapter.getAnnotation('iso-a2')).toEqual(expectedAnn);
        expect(await adapter.getRelink('iso-r2')).toEqual(expectedRlk);
      });

      it('getModelDescriptor returns a detached row whose descriptor is parsed from canonicalBytes', async () => {
        const { digest } = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        const row = (await adapter.getModelDescriptor(digest))!;
        expect(JSON.parse(row.canonicalBytes)).toEqual(row.descriptor);
        row.descriptor.modelName = 'TAMPERED';
        row.canonicalBytes = '{}';
        row.descriptor.regulatoryMarkings.push({ authority: 'x', identifier: 'y' } as never);
        const again = (await adapter.getModelDescriptor(digest))!;
        expect(again.descriptor.modelName).toBe('claude-opus-4-7');
        expect(again.descriptor.regulatoryMarkings).toEqual([]);
        expect(JSON.parse(again.canonicalBytes)).toEqual(again.descriptor);
      });

      it('listModelDescriptorAnnotations returns detached copies', async () => {
        const { digest } = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        await adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(digest, { annotationId: 'iso-mda' }));
        (await adapter.listModelDescriptorAnnotations(digest))[0].valueJson = '{"tampered":true}';
        expect((await adapter.listModelDescriptorAnnotations(digest))[0].valueJson).toBe('{"text":"looks right"}');
      });

      it('a descriptor tamper through the demo hook is visible through descriptor, not only canonicalBytes', async () => {
        // The demo's phase-5 tamper. Every adapter reads `descriptor` from the
        // stored canonical bytes, so the tampered model name shows in both. An
        // adapter that kept a second, parsed copy would show the tampered bytes
        // beside a clean model name.
        const { digest } = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        await armDemoHooks(adapter);
        const row = (await adapter.getModelDescriptor(digest))!;
        const mutated = row.canonicalBytes.replace('"claude-opus-4-7"', '"claude-opus-4-7 (retroactively edited)"');
        expect(mutated).not.toBe(row.canonicalBytes);
        const previous = await adapter.overwriteModelDescriptorBytesForDemo!(digest, mutated);
        expect(previous).toBe(row.canonicalBytes);
        const after = (await adapter.getModelDescriptor(digest))!;
        expect(after.canonicalBytes).toBe(mutated);
        expect(after.descriptor.modelName).toBe('claude-opus-4-7 (retroactively edited)');
      });

      it('the demo re-seat pattern — delete the head, re-store it byte-for-byte — leaves chain_state naming the head', async () => {
        // The demo application's rewriteStoredEnvelope()/reseatChainHead():
        // what it needs from every adapter is that a record it holds a
        // (detached) copy of can be deleted through the hook and put back
        // through store(), and that the last write to chain_state is then the
        // head's own digest again.
        const first = makeEnvelope({ evidenceId: 'seat-1', sequenceNumber: 1, digest: '1'.repeat(64) });
        const head = makeEnvelope({ evidenceId: 'seat-2', sequenceNumber: 2, digest: '2'.repeat(64) });
        await adapter.store(first, 'default');
        await adapter.store(head, 'default');
        await armDemoHooks(adapter);
        const held = (await adapter.retrieve('seat-2'))!;
        const chainId = await adapter.getChainForRecord('seat-2');
        await adapter.deleteEnvelopeForDemo!('seat-2');
        expect(await adapter.retrieve('seat-2')).toBeNull();
        await adapter.store(held, chainId ?? undefined);
        expect(await adapter.retrieve('seat-2')).toEqual(snapshot(head));
        expect(await adapter.getLastDigest()).toBe(head.integrity.canonicalDigest);
        expect(await adapter.getChainLength('default')).toBe(2);
      });

      it('the demo rewrite pattern — delete a record, re-store a tampered copy under its id, re-seat the head — persists the tamper and leaves chain_state naming the head', async () => {
        // The demo application's rewriteStoredEnvelope(replacement, head).
        // Every read is detached, so assigning to what retrieve() returned
        // changes nothing in the store, on any adapter. The pattern that works
        // on every adapter goes through the hook: delete the row, store the
        // mutated copy, put the head pointer back.
        // Snapshot BEFORE storing: an adapter that keeps the caller's object
        // would otherwise move `first` along with the tamper below.
        const first = snapshot(makeEnvelope({ evidenceId: 'rw-1', sequenceNumber: 1, digest: '1'.repeat(64) }));
        const head = snapshot(makeEnvelope({ evidenceId: 'rw-2', sequenceNumber: 2, digest: '2'.repeat(64) }));
        await adapter.store(snapshot(first), 'default');
        await adapter.store(snapshot(head), 'default');
        await armDemoHooks(adapter);

        const replacement = (await adapter.retrieve('rw-1'))!;
        replacement.payload.reason = 'Approved — retroactively edited';
        // The assignment alone changes nothing in the store, on any adapter.
        expect((await adapter.retrieve('rw-1'))!.payload.reason).toBe(first.payload.reason);

        const chainId = await adapter.getChainForRecord('rw-1');
        await adapter.deleteEnvelopeForDemo!('rw-1');
        await adapter.store(replacement, chainId ?? undefined);
        // chain_state now names the rewritten record; the demo re-seats it.
        expect(await adapter.getLastDigest()).toBe(first.integrity.canonicalDigest);
        const heldHead = (await adapter.retrieve('rw-2'))!;
        const headChain = await adapter.getChainForRecord('rw-2');
        await adapter.deleteEnvelopeForDemo!('rw-2');
        await adapter.store(heldHead, headChain ?? undefined);

        const tampered = (await adapter.retrieve('rw-1'))!;
        expect(tampered.payload.reason).toBe('Approved — retroactively edited');
        // The digest was left alone, so this is the digest_mismatch a verifier sees.
        expect(tampered.integrity.canonicalDigest).toBe(first.integrity.canonicalDigest);
        expect(await adapter.getLastDigest()).toBe(head.integrity.canonicalDigest);
        expect(await adapter.getChainLength('default')).toBe(2);
        expect(ids(await adapter.listBySequence(1, undefined, 'default'))).toEqual(['rw-1', 'rw-2']);
      });
    });


    // ── Append-only tables refuse a second write ───────────────────
    //
    // storeChain, storeAnnotation, storeRelink, storeFork and
    // appendModelDescriptorAnnotation are a bare INSERT against a primary key
    // (and a foreign key) on SQLite and Postgres, and the memory adapter
    // refuses the same writes. Every adapter throws the SDK's own
    // DuplicateRecordError / MissingReferenceError, so one `catch` means the
    // same thing on all three, and a second storeChain for an existing id
    // cannot silently replace a chain identity in development while it throws
    // in production.

    describe('append-only refusal', () => {
      it('storeChain refuses a second identity for the same chainId and leaves the first untouched', async () => {
        await adapter.storeChain(makeChain({ chainId: 'ao-c', status: 'active' }));
        const attempt = adapter.storeChain(makeChain({ chainId: 'ao-c', status: 'sealed', sealedAt: '2026-04-05T00:00:00.000Z' }));
        await expect(attempt).rejects.toThrow(DuplicateRecordError);
        await expect(attempt).rejects.toMatchObject({ code: 'duplicate_record', recordId: 'ao-c' });
        expect((await adapter.getChain('ao-c'))!.status).toBe('active');
        expect((await adapter.getChain('ao-c'))!.sealedAt).toBeUndefined();
      });

      it('storeAnnotation refuses a duplicate id and leaves the first untouched', async () => {
        await adapter.storeAnnotation(makeAnnotation({ id: 'ao-a', notes: 'first' }));
        const attempt = adapter.storeAnnotation(makeAnnotation({ id: 'ao-a', notes: 'second' }));
        await expect(attempt).rejects.toThrow(DuplicateRecordError);
        expect((await adapter.getAnnotation('ao-a'))!.notes).toBe('first');
      });

      it('storeRelink refuses a duplicate id and leaves the first untouched', async () => {
        await adapter.storeRelink(makeRelink({ id: 'ao-r', toSequence: 2 }));
        const attempt = adapter.storeRelink(makeRelink({ id: 'ao-r', toSequence: 9 }));
        await expect(attempt).rejects.toThrow(DuplicateRecordError);
        expect((await adapter.getRelink('ao-r'))!.toSequence).toBe(2);
      });

      it('storeFork refuses a duplicate id and leaves the first untouched', async () => {
        await adapter.storeFork(makeFork({ id: 'ao-f', reason: 'first' }));
        const attempt = adapter.storeFork(makeFork({ id: 'ao-f', reason: 'second' }));
        await expect(attempt).rejects.toThrow(DuplicateRecordError);
        expect((await adapter.getFork('ao-f'))!.reason).toBe('first');
      });

      it('appendModelDescriptorAnnotation refuses a duplicate annotationId', async () => {
        const { digest } = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        await adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(digest, { annotationId: 'ao-mda' }));
        const attempt = adapter.appendModelDescriptorAnnotation(
          makeDescriptorAnnotation(digest, { annotationId: 'ao-mda', valueJson: '{"second":true}' }),
        );
        await expect(attempt).rejects.toThrow(DuplicateRecordError);
        const log = await adapter.listModelDescriptorAnnotations(digest);
        expect(log).toHaveLength(1);
        expect(log[0].valueJson).toBe('{"text":"looks right"}');
      });

      it('appendModelDescriptorAnnotation for a descriptor that was never registered is refused', async () => {
        const orphan = 'sha256:' + '0'.repeat(64);
        const attempt = adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(orphan, { annotationId: 'ao-orphan' }));
        await expect(attempt).rejects.toThrow(MissingReferenceError);
        await expect(attempt).rejects.toMatchObject({ code: 'missing_reference', referenceId: orphan });
        expect(await adapter.listModelDescriptorAnnotations(orphan)).toEqual([]);
      });
    });


    // ── list() ordering ────────────────────────────────────────────
    //
    // list() orders by the UTC instant of capturedAt on every backend.
    // Postgres (TIMESTAMPTZ) compares instants; a comparison of the raw
    // strings (`localeCompare`, or `ORDER BY` on a TEXT column) would give a
    // customer whose timestamps are not uniform ms-precision UTC a
    // chronologically wrong evidence list on the two local backends and a
    // correct one in the cloud. The contract is stated once in
    // src/storage/list-order.ts; these cases hold it on all three.

    describe('list ordering', () => {
      it('orders by the UTC instant of capturedAt, not the string: mixed precision', async () => {
        // Lexicographically '.' (0x2E) < 'Z' (0x5A), so a string sort puts the LATER record first.
        await adapter.store(makeEnvelope({ evidenceId: 'p-b', sequenceNumber: 1, capturedAt: '2026-05-01T10:00:00.500Z' }));
        await adapter.store(makeEnvelope({ evidenceId: 'p-a', sequenceNumber: 2, capturedAt: '2026-05-01T10:00:00Z' }));
        expect(ids(await adapter.list({ order: 'asc' }))).toEqual(['p-a', 'p-b']);
        expect(ids(await adapter.list({ order: 'desc' }))).toEqual(['p-b', 'p-a']);
      });

      it('orders by the UTC instant of capturedAt: a non-UTC offset is converted, not compared by its digits', async () => {
        // o-a is 10:00Z written as 12:00+02:00; o-b is 10:30Z.
        await adapter.store(makeEnvelope({ evidenceId: 'o-b', sequenceNumber: 1, capturedAt: '2026-05-01T10:30:00Z' }));
        await adapter.store(makeEnvelope({ evidenceId: 'o-a', sequenceNumber: 2, capturedAt: '2026-05-01T12:00:00+02:00' }));
        expect(ids(await adapter.list({ order: 'asc' }))).toEqual(['o-a', 'o-b']);
        expect(ids(await adapter.list({ order: 'desc' }))).toEqual(['o-b', 'o-a']);
      });

      it('breaks ties on an identical capturedAt by sequenceNumber then evidenceId, and desc is the exact reverse of asc', async () => {
        const at = '2026-05-01T10:00:00.000Z';
        await adapter.store(makeEnvelope({ evidenceId: 't-1', sequenceNumber: 1, capturedAt: at }));
        await adapter.store(makeEnvelope({ evidenceId: 't-2', sequenceNumber: 2, capturedAt: at }));
        await adapter.store(makeEnvelope({ evidenceId: 't-3', sequenceNumber: 3, capturedAt: at }));
        // Same instant AND same sequence (two forked chains, each restarting at 1): evidenceId decides.
        await adapter.store(makeEnvelope({ evidenceId: 'z-1', sequenceNumber: 1, capturedAt: at }), 'forked');
        await adapter.store(makeEnvelope({ evidenceId: 'a-1', sequenceNumber: 1, capturedAt: at }), 'forked-b');
        const asc = ids(await adapter.list({ order: 'asc' }));
        expect(asc).toEqual(['a-1', 't-1', 'z-1', 't-2', 't-3']);
        expect(ids(await adapter.list({ order: 'desc' }))).toEqual([...asc].reverse());
      });

      it('compares instants at millisecond precision, truncating sub-millisecond digits', async () => {
        // Both truncate to .000 — a tie, decided by sequenceNumber — and the
        // nanosecond-precision 0.123456789 truncates to .123, before .124.
        await adapter.store(makeEnvelope({ evidenceId: 'sub-b', sequenceNumber: 1, capturedAt: '2026-05-01T10:00:00.000100Z' }));
        await adapter.store(makeEnvelope({ evidenceId: 'sub-a', sequenceNumber: 2, capturedAt: '2026-05-01T10:00:00.000900Z' }));
        await adapter.store(makeEnvelope({ evidenceId: 'ms-124', sequenceNumber: 3, capturedAt: '2026-05-01T10:00:00.124Z' }));
        await adapter.store(makeEnvelope({ evidenceId: 'nano-123', sequenceNumber: 4, capturedAt: '2026-05-01T10:00:00.123456789Z' }));
        expect(ids(await adapter.list({ order: 'asc' }))).toEqual(['sub-b', 'sub-a', 'nano-123', 'ms-124']);
      });

      it('the default order is desc', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'd-1', sequenceNumber: 1, capturedAt: '2026-05-01T10:00:00.000Z' }));
        await adapter.store(makeEnvelope({ evidenceId: 'd-2', sequenceNumber: 2, capturedAt: '2026-05-01T11:00:00.000Z' }));
        expect(ids(await adapter.list())).toEqual(['d-2', 'd-1']);
      });

      it('filters by aiSystemId and by chainId, then orders', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'f-1', sequenceNumber: 1, aiSystemId: 'sys-a', capturedAt: '2026-05-01T10:00:00.000Z' }), 'chain-x');
        await adapter.store(makeEnvelope({ evidenceId: 'f-2', sequenceNumber: 2, aiSystemId: 'sys-b', capturedAt: '2026-05-01T11:00:00.000Z' }), 'chain-x');
        await adapter.store(makeEnvelope({ evidenceId: 'f-3', sequenceNumber: 1, aiSystemId: 'sys-a', capturedAt: '2026-05-01T12:00:00.000Z' }), 'chain-y');
        expect(ids(await adapter.list({ aiSystemId: 'sys-a', order: 'asc' }))).toEqual(['f-1', 'f-3']);
        expect(ids(await adapter.list({ chainId: 'chain-x', order: 'asc' }))).toEqual(['f-1', 'f-2']);
        expect(ids(await adapter.list({ chainId: 'chain-x', aiSystemId: 'sys-b' }))).toEqual(['f-2']);
      });

      it('limit and offset are applied after ordering', async () => {
        for (let i = 1; i <= 5; i++) {
          await adapter.store(makeEnvelope({ evidenceId: `pg-${i}`, sequenceNumber: i, capturedAt: `2026-05-01T10:0${i}:00.000Z` }));
        }
        expect(ids(await adapter.list({ order: 'asc', limit: 2 }))).toEqual(['pg-1', 'pg-2']);
        expect(ids(await adapter.list({ order: 'asc', limit: 2, offset: 2 }))).toEqual(['pg-3', 'pg-4']);
        expect(ids(await adapter.list({ order: 'desc', offset: 3 }))).toEqual(['pg-2', 'pg-1']);
        expect(ids(await adapter.list({ order: 'asc', limit: 0 }))).toEqual([]);
      });
    });


    // ── Pagination guard, alias ties, ledger order ────────────────

    describe('pagination guard', () => {
      // Every adapter refuses a limit or offset that is not a non-negative
      // integer with InvalidPaginationError. Used raw, the value is silent
      // data loss in a slice (`list({limit: -1})` gives n-1 rows), and as a
      // bound SQL parameter a DatabaseError for -1 or a coerced string for "2".
      it('list rejects a negative limit with InvalidPaginationError instead of dropping a row', async () => {
        for (let i = 1; i <= 3; i++) await adapter.store(makeEnvelope({ evidenceId: `g-${i}`, sequenceNumber: i }));
        await expect(adapter.list({ limit: -1 })).rejects.toThrow(InvalidPaginationError);
        await expect(adapter.list({ limit: -1 })).rejects.toThrow('Invalid limit: expected a non-negative integer, received -1.');
      });

      it('list rejects a string limit — a forwarded req.query.limit — rather than coercing it', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'g-1' }));
        await expect(adapter.list({ limit: '2' as unknown as number })).rejects.toThrow(InvalidPaginationError);
        await expect(adapter.list({ limit: '2' as unknown as number })).rejects.toThrow('received "2"');
      });

      it('list rejects a negative, fractional or non-finite offset', async () => {
        await adapter.store(makeEnvelope({ evidenceId: 'g-1' }));
        await expect(adapter.list({ offset: -1 })).rejects.toThrow(InvalidPaginationError);
        await expect(adapter.list({ offset: 1.5 })).rejects.toThrow(InvalidPaginationError);
        await expect(adapter.list({ offset: Number.POSITIVE_INFINITY })).rejects.toThrow(InvalidPaginationError);
        await expect(adapter.list({ limit: Number.NaN })).rejects.toThrow(InvalidPaginationError);
      });

      it('listModelDescriptors applies the same guard, with and without a post-filter', async () => {
        await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        await expect(adapter.listModelDescriptors({ limit: -1 })).rejects.toThrow(InvalidPaginationError);
        await expect(adapter.listModelDescriptors({ offset: '1' as unknown as number })).rejects.toThrow(InvalidPaginationError);
        await expect(adapter.listModelDescriptors({ integrityTier: 'vendor-asserted', limit: -1 })).rejects.toThrow(InvalidPaginationError);
        expect(await adapter.listModelDescriptors({ limit: 1 })).toHaveLength(1);
      });
    });

    describe('catalog aliases and annotations', () => {
      it('two alias binds in the same millisecond do not collide, and the later one wins', async () => {
        // (slug, setAt) is the key at millisecond resolution, so two binds in
        // one millisecond collide on it. Every adapter keeps the later binding,
        // rather than raising a key violation or keeping the first.
        // Force the collision instead of hoping for it.
        const a = await adapter.registerModelDescriptor(makeDescriptor({ modelVersion: 'a' }), 'manual', 't');
        const b = await adapter.registerModelDescriptor(makeDescriptor({ modelVersion: 'b' }), 'manual', 't');
        const frozen = jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2026-05-01T10:00:00.000Z');
        try {
          await adapter.setModelDescriptorAlias('current', a.digest, 'admin');
          await adapter.setModelDescriptorAlias('current', b.digest, 'admin');
        } finally {
          frozen.mockRestore();
        }
        expect(await adapter.resolveModelDescriptorAlias('current')).toBe(b.digest);
        // A later instant still wins over the collapsed one.
        await new Promise((r) => setTimeout(r, 5));
        await adapter.setModelDescriptorAlias('current', a.digest, 'admin');
        expect(await adapter.resolveModelDescriptorAlias('current')).toBe(a.digest);
      });

      it('listModelDescriptorAnnotations is ordered by annotatedAt then annotationId, not by insertion', async () => {
        const { digest } = await adapter.registerModelDescriptor(makeDescriptor(), 'manual', 't');
        await adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(digest, { annotationId: 'an-c', annotatedAt: '2026-05-03T00:00:00.000Z' }));
        await adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(digest, { annotationId: 'an-a', annotatedAt: '2026-05-01T00:00:00.000Z' }));
        await adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(digest, { annotationId: 'an-b', annotatedAt: '2026-05-02T00:00:00.000Z' }));
        // Same instant: annotationId decides.
        await adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(digest, { annotationId: 'an-b2', annotatedAt: '2026-05-02T00:00:00.000Z' }));
        await adapter.appendModelDescriptorAnnotation(makeDescriptorAnnotation(digest, { annotationId: 'an-b1', annotatedAt: '2026-05-02T00:00:00.000Z' }));
        expect((await adapter.listModelDescriptorAnnotations(digest)).map((a) => a.annotationId))
          .toEqual(['an-a', 'an-b', 'an-b1', 'an-b2', 'an-c']);
      });
    });

    describe('incident and ledger ordering', () => {
      it('listIncidents is ordered by detectedAt descending, ties by id descending', async () => {
        await adapter.storeIncident(makeIncident({ id: 'i-old', detectedAt: '2026-04-01T00:00:00.000Z' }));
        await adapter.storeIncident(makeIncident({ id: 'i-new', detectedAt: '2026-04-03T00:00:00.000Z' }));
        await adapter.storeIncident(makeIncident({ id: 'i-mid-a', detectedAt: '2026-04-02T00:00:00.000Z' }));
        await adapter.storeIncident(makeIncident({ id: 'i-mid-b', detectedAt: '2026-04-02T00:00:00.000Z' }));
        expect((await adapter.listIncidents()).map((i) => i.id)).toEqual(['i-new', 'i-mid-b', 'i-mid-a', 'i-old']);
      });

      it('listChains is ordered by createdAt ascending, ties by chainId', async () => {
        await adapter.storeChain(makeChain({ chainId: 'c-late', createdAt: '2026-04-02T00:00:00.000Z' }));
        await adapter.storeChain(makeChain({ chainId: 'c-early-b', createdAt: '2026-04-01T00:00:00.000Z' }));
        await adapter.storeChain(makeChain({ chainId: 'c-early-a', createdAt: '2026-04-01T00:00:00.000Z' }));
        expect((await adapter.listChains()).map((c) => c.chainId)).toEqual(['c-early-a', 'c-early-b', 'c-late']);
      });

      it('listAnnotations, listRelinks and listForks are ordered by their timestamp ascending, ties by id', async () => {
        await adapter.storeAnnotation(makeAnnotation({ id: 'a-2', annotatedAt: '2026-04-02T00:00:00.000Z' }));
        await adapter.storeAnnotation(makeAnnotation({ id: 'a-1b', annotatedAt: '2026-04-01T00:00:00.000Z' }));
        await adapter.storeAnnotation(makeAnnotation({ id: 'a-1a', annotatedAt: '2026-04-01T00:00:00.000Z' }));
        await adapter.storeRelink(makeRelink({ id: 'r-2', relinkedAt: '2026-04-02T00:00:00.000Z' }));
        await adapter.storeRelink(makeRelink({ id: 'r-1', relinkedAt: '2026-04-01T00:00:00.000Z' }));
        await adapter.storeFork(makeFork({ id: 'f-2', forkedAt: '2026-04-02T00:00:00.000Z', oldChainId: 'x', newChainId: 'y' }));
        await adapter.storeFork(makeFork({ id: 'f-1', forkedAt: '2026-04-01T00:00:00.000Z', oldChainId: 'y', newChainId: 'z' }));
        expect((await adapter.listAnnotations('inc-001')).map((a) => a.id)).toEqual(['a-1a', 'a-1b', 'a-2']);
        expect((await adapter.listAnnotationsForRecord('ev-001')).map((a) => a.id)).toEqual(['a-1a', 'a-1b', 'a-2']);
        expect((await adapter.listRelinks('inc-001')).map((r) => r.id)).toEqual(['r-1', 'r-2']);
        expect((await adapter.listForks('inc-001')).map((f) => f.id)).toEqual(['f-1', 'f-2']);
        expect((await adapter.listForksForChain('y')).map((f) => f.id)).toEqual(['f-1', 'f-2']);
      });
    });

    // ── Round-tripping: what JSON storage does to a payload ──────────────
    //
    // These pin the shape of a stored payload so it cannot drift silently.
    // Postgres JSONB is the reference: `undefined`-valued keys vanish and -0
    // becomes 0 on every backend. Key order is the one thing JSONB cannot
    // promise, so that is an ASSERTED DIVERGENCE, not a skip.

    describe('payload round-tripping', () => {
      if (caps.backend === 'postgres') {
        it('ASSERTED DIVERGENCE: Postgres JSONB does not preserve object key order', async () => {
          await adapter.store(makeEnvelope({ evidenceId: 'k-1', aiOutput: { zebra: 1, alpha: 2, m: 3 } }));
          const got = (await adapter.retrieve('k-1'))!;
          expect(Object.keys(got.payload.aiOutput).sort()).toEqual(['alpha', 'm', 'zebra']);
          expect(Object.keys(got.payload.aiOutput)).not.toEqual(['zebra', 'alpha', 'm']);
        });
      } else {
        it('object key order is preserved on retrieve (memory, SQLite; Postgres JSONB reorders)', async () => {
          await adapter.store(makeEnvelope({ evidenceId: 'k-1', aiOutput: { zebra: 1, alpha: 2, m: 3 } }));
          const got = (await adapter.retrieve('k-1'))!;
          expect(Object.keys(got.payload.aiOutput)).toEqual(['zebra', 'alpha', 'm']);
        });
      }

      // A payload string containing U+0000 captures on memory and SQLite
      // and hard-fails on Postgres (jsonb cannot represent it). The remedy is
      // validation at capture() time, on every backend, which is NOT the
      // adapters' job. Until capture() validates, the adapter-level fact is
      // pinned both ways:
      // Postgres refuses (a customer sees this today), and the two local
      // backends are EXPECTED-FAIL on the converged behaviour, so the day an
      // adapter starts refusing, the it.failing flips and the pin below it
      // has to be retired together with this comment.
      const nul = 'before' + String.fromCharCode(0) + 'after';
      if (caps.backend === 'postgres') {
        it('a payload string containing U+0000 is refused by the store', async () => {
          await expect(adapter.store(makeEnvelope({ evidenceId: 'nul-1', reason: nul })))
            .rejects.toThrow(/unsupported Unicode escape sequence/);
          expect(await adapter.retrieve('nul-1')).toBeNull();
        });
      } else {
        it.failing('a payload string containing U+0000 is refused by the store (expected-fail: memory and SQLite accept it today; fix is capture-time validation)', async () => {
          await expect(adapter.store(makeEnvelope({ evidenceId: 'nul-1', reason: nul })))
            .rejects.toThrow();
        });

        it('ASSERTED DIVERGENCE: a payload string containing U+0000 round-trips on memory and SQLite', async () => {
          await adapter.store(makeEnvelope({ evidenceId: 'nul-2', reason: nul }));
          expect((await adapter.retrieve('nul-2'))!.payload.reason).toBe(nul);
        });
      }
    });
  });
}
