// The sealed-chain bound on the Postgres adapter — the twin of
// `sealed-chain-bound-is-a-sequence.test.ts`, which explains why the bound is
// a sequence and not a row count. This file exists because the fork record is
// a TABLE ROW here: the head is a column, and a NULL in it has to read back
// as "no head recorded" through pg's own type mapping. Neither the memory nor
// the SQLite path exercises that.
//
// Runs when the Postgres legs do (tests/ts/helpers/postgres-test-db.ts), in a
// schema of the file's own. Each case starts from that schema EMPTY — the
// helper's `reset()` — so `ensureTables()` builds the store from nothing and
// the no-head cases can then take the column away again.
//
// Tampering goes through a raw `pg` Pool with `session_replication_role =
// 'replica'`, which is how the adapter's own demo hook steps around the
// append-only triggers — an edit made outside the SDK, which is what tampering
// is.
import { Pool } from 'pg';
import { Tzun } from '../../src/sdk/index';
import { chainUpperBound } from '../../src/storage/chain-bounds';
import { ForkRecord, TamperIncident } from '@tzun/engine';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const schema = pgSuiteSchema('sealed_chain_bound');
const describeLive = PG_TESTS_ENABLED ? describe : describe.skip;

function boot(): Promise<Tzun> {
  return Tzun.init({ mode: 'dev', dbUrl: schema.url });
}

/** DELETE one envelope row past the append-only triggers. */
async function deleteRecord(pool: Pool, evidenceId: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    const result = await client.query('DELETE FROM envelopes WHERE evidence_id = $1', [evidenceId]);
    if (result.rowCount !== 1) throw new Error(`expected to delete 1 row for ${evidenceId}, deleted ${result.rowCount}`);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => { /* ignore */ });
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Take the head column off the store, so every fork row in it reads back with
 * no head — the state `forkFromRow()` turns into an absent
 * `sealedOldChainHead` key and `chainUpperBound()` recomputes a bound for.
 */
async function dropHeadColumn(pool: Pool): Promise<void> {
  await pool.query('ALTER TABLE chain_forks DROP COLUMN sealed_old_chain_head');
}

async function forkColumns(pool: Pool): Promise<string[]> {
  // Schema-qualified on purpose: information_schema.columns lists every
  // schema the role can see, so an unqualified read can be answered by a
  // same-named table in another one — every other suite's, in a shared run.
  const result = await pool.query(
    "SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'chain_forks'",
    [schema.name],
  );
  return result.rows.map((r: { column_name: string }) => r.column_name);
}

function incidentFor(evidenceIds: string[], id: string): TamperIncident {
  return {
    id,
    detectedAt: new Date().toISOString(),
    severity: 'critical',
    type: 'sequence_gap',
    affectedRecords: evidenceIds,
    details: 'A record was deleted.',
    status: 'open',
  };
}

interface Fixture {
  sealedChainId: string;
  ids: Map<number, string>;
  fork: ForkRecord;
}

/** Five captures; record 4 deleted (the gap) unless `gap` is false; fork after 3. */
async function gappedThenSealed(pool: Pool, gap = true): Promise<Fixture> {
  let tzun = await boot();
  const ids = new Map<number, string>();
  try {
    for (let i = 1; i <= 5; i++) {
      const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `record-${i}` });
      expect(result.failure).toBeUndefined();
      expect(result.stored).toBe(true);
      ids.set(result.envelope.payload.sequenceNumber, result.envelope.payload.evidenceId);
    }
  } finally {
    await tzun.close();
  }
  if (gap) await deleteRecord(pool, ids.get(4)!);

  tzun = await boot();
  try {
    const sealedChainId = await tzun.getActiveChainId();
    const forked = await tzun.recovery.fork('inc-sealed-bound-fork', {
      authorizedBy: 'admin@acme.example',
      reason: 'A record was deleted; sealing the chain.',
      forkAfterSequence: 3,
    });
    return { sealedChainId, ids, fork: forked.fork };
  } finally {
    await tzun.close();
  }
}

describeLive('the sealed chain bound is a sequence, not a row count (live Postgres)', () => {
  jest.setTimeout(60_000);
  let pool: Pool;

  // Every case forks the `default` chain, and the last one also drops the
  // head column; all of it stays in this file's schema, which the helper
  // drops after the last case.
  beforeAll(() => { pool = new Pool({ connectionString: schema.url }); });
  afterAll(async () => { await pool.end(); });
  beforeEach(() => schema.reset());

  it('fork() records the head sequence distinctly from the row count, and the adapter persists it', async () => {
    const { sealedChainId, fork } = await gappedThenSealed(pool);
    expect(fork.sealedOldChainLength).toBe(4);
    expect(fork.sealedOldChainHead).toBe(5);

    const raw = await pool.query('SELECT sealed_old_chain_length, sealed_old_chain_head FROM chain_forks WHERE id = $1', [fork.id]);
    expect(raw.rows[0]).toEqual({ sealed_old_chain_length: 4, sealed_old_chain_head: 5 });

    const tzun = await boot();
    try {
      const storage = tzun.getStorage();
      const stored = await storage.listForksForChain(sealedChainId);
      expect(stored).toHaveLength(1);
      expect(stored[0].sealedOldChainLength).toBe(4);
      expect(stored[0].sealedOldChainHead).toBe(5);
      expect(await storage.getFork(fork.id)).toEqual(stored[0]);
      expect(await chainUpperBound(storage, sealedChainId)).toBe(5);
    } finally {
      await tzun.close();
    }
  });

  it('verifyChainCompleteness(sealed) reports a deleted TAIL on a sealed chain that has a gap', async () => {
    const { sealedChainId, ids } = await gappedThenSealed(pool);
    await deleteRecord(pool, ids.get(5)!);

    const tzun = await boot();
    try {
      expect(await tzun.getActiveChainId()).not.toBe(sealedChainId);
      const result = await tzun.verifyChainCompleteness(sealedChainId);
      expect(result.valid).toBe(false);
      // 4 is the gap; 5 is the deleted tail. A row-count bound would report
      // only [4].
      expect(result.sequenceGaps).toEqual([4, 5]);
      expect(result.totalRecords).toBe(3);
      expect(result.lastRecord).toBe(3);
    } finally {
      await tzun.close();
    }
  });

  it("relink()'s reported range covers the sealed chain's tail, and the orphaned tail is actually re-linked", async () => {
    const { sealedChainId, ids } = await gappedThenSealed(pool);

    const tzun = await boot();
    try {
      await tzun.getStorage().storeIncident(incidentFor([ids.get(4)!, ids.get(5)!], 'inc-sealed-bound-relink'));
      const result = await tzun.recovery.relink('inc-sealed-bound-relink', {
        chainId: sealedChainId,
        fromSequence: 3,
        authorizedBy: 'admin@acme.example',
      });
      // A row-count bound would give toSequence 4 and modifiedLinks [].
      expect(result.relink.toSequence).toBe(5);
      expect(result.relink.modifiedLinks.map((l) => l.sequenceNumber)).toEqual([5]);
      expect(result.chainVerified).toBe(true);

      const after = await tzun.verifyChainCompleteness(sealedChainId);
      expect(after.brokenLinks).toEqual([]);
      expect(after.sequenceGaps).toEqual([4]);
      expect(after.lastRecord).toBe(5);
    } finally {
      await tzun.close();
    }
  });

  it('ensureTables builds chain_forks WITH sealed_old_chain_head, on a schema that starts empty', async () => {
    const tzun = await boot();
    try {
      expect(await forkColumns(pool)).toContain('sealed_old_chain_head');

      // And a fork on that store persists its head.
      for (let i = 1; i <= 2; i++) {
        const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `new-chain-${i}` });
        expect(result.stored).toBe(true);
      }
      const second = await tzun.recovery.fork('inc-sealed-bound-fresh', {
        authorizedBy: 'admin@acme.example',
        reason: 'Fork on a store built from the designed schema.',
        forkAfterSequence: 1,
      });
      expect(second.fork.sealedOldChainHead).toBe(2);
      const raw = await pool.query(`SELECT sealed_old_chain_head FROM ${schema.name}.chain_forks WHERE id = $1`, [second.fork.id]);
      expect(raw.rows[0]).toEqual({ sealed_old_chain_head: 2 });
    } finally {
      await tzun.close();
    }
  });

  it('a row with no head reads back with no head, and the bound is recomputed from the records — not the row count', async () => {
    const { sealedChainId, fork } = await gappedThenSealed(pool);
    await dropHeadColumn(pool);

    const tzun = await boot();
    try {
      const storage = tzun.getStorage();
      const [headless] = await storage.listForksForChain(sealedChainId);
      expect(headless.id).toBe(fork.id);
      expect(headless.sealedOldChainLength).toBe(4);
      expect('sealedOldChainHead' in headless).toBe(false);
      expect(await storage.getFork(fork.id)).toEqual(headless);
      expect(await chainUpperBound(storage, sealedChainId)).toBe(5);

      const result = await tzun.verifyChainCompleteness(sealedChainId);
      expect(result.sequenceGaps).toEqual([4]);
      expect(result.lastRecord).toBe(5);
      expect(result.totalRecords).toBe(4);
    } finally {
      await tzun.close();
    }
  });

  it('a GAPLESS chain with no recorded head still has a deleted tail detected: the row count is kept as a lower bound', async () => {
    const { sealedChainId, ids } = await gappedThenSealed(pool, false);
    await dropHeadColumn(pool);
    await deleteRecord(pool, ids.get(5)!);

    const tzun = await boot();
    try {
      const result = await tzun.verifyChainCompleteness(sealedChainId);
      expect(result.valid).toBe(false);
      expect(result.sequenceGaps).toEqual([5]);
      expect(result.lastRecord).toBe(4);
    } finally {
      await tzun.close();
    }
  });
});
