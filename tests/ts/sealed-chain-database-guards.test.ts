/**
 * A sealed chain, and the bound that keeps its tail detectable, are enforced
 * by the database on both SQL adapters.
 *
 * Two guarantees protect a sealed chain: nothing is appended to it, and its
 * tail cannot be cut undetected. The first rests on `chains.status`, which
 * `assertChainNotSealed()` reads inside every append; the second rests on
 * `chain_forks.sealed_old_chain_head`, which `chainUpperBound()` hands every
 * verifier as the sealed chain's high-water mark. Without a trigger on those
 * tables, any writer to the store could lift a seal with one UPDATE, or lower
 * the recorded head to match a deleted tail; the triggers refuse both.
 *
 * Every attack below is a raw statement on the adapter's own connection —
 * behind the adapter's back, the way an insider with write access would do
 * it.
 *
 * Legs: sqlite always (a temp file per case). postgres when the Postgres legs
 * run (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own;
 * every chain and fork id carries a run-unique suffix.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { NoActiveChainError } from '@tzun/engine';
import type { StorageAdapter } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { chainUpperBound } from '../../src/storage/chain-bounds';
import { makeChain, makeEnvelope, makeFork } from './storage-conformance/fixtures';

interface Leg {
  name: 'sqlite' | 'postgres';
  make: () => Promise<{ adapter: StorageAdapter; teardown: () => Promise<void> }>;
  /** Run one raw statement on the adapter's own connection. `?` placeholders on both legs. */
  raw: (adapter: StorageAdapter, sql: string, params?: unknown[]) => Promise<void>;
}

const sqliteLeg: Leg = {
  name: 'sqlite',
  make: async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-'));
    const adapter = new SqliteStorageAdapter(path.join(dir, 'sealed.db'));
    return {
      adapter,
      teardown: async () => {
        await adapter.close();
        fs.rmSync(dir, { recursive: true, force: true });
      },
    };
  },
  raw: async (adapter, sql, params = []) => {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    db.prepare(sql).run(...params);
  },
};

const pgSchema = pgSuiteSchema('sealed_chain_guards');

const postgresLeg: Leg = {
  name: 'postgres',
  make: async () => {
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    return { adapter, teardown: async () => adapter.close() };
  },
  raw: async (adapter, sql, params = []) => {
    const pool = (adapter as unknown as { pool: import('pg').Pool }).pool;
    let n = 0;
    await pool.query(sql.replace(/\?/g, () => `$${++n}`), params);
  },
};

const legs: Leg[] = PG_TESTS_ENABLED ? [sqliteLeg, postgresLeg] : [sqliteLeg];

/**
 * The message a raw statement was refused with, or a throw if it went through.
 * Read off `.message` rather than via `rejects.toThrow`, which does not
 * recognise a better-sqlite3 error built in another test file's realm (see
 * `refusalMessage` in custody-trail-hashed-and-atomic.test.ts).
 */
async function refusal(run: () => Promise<void>): Promise<string> {
  try {
    await run();
  } catch (err) {
    const message = (err as { message?: unknown } | null)?.message;
    return typeof message === 'string' ? message : String(err);
  }
  throw new Error('expected the statement to be refused, but it went through');
}

let counter = 0;
const unique = (label: string): string =>
  `${label}-${Date.now().toString(36)}-${(counter += 1)}-${Math.random().toString(36).slice(2, 8)}`;

describe.each(legs)('sealed chains are enforced by the database — $name adapter', (leg) => {
  let adapter: StorageAdapter;
  let teardown: () => Promise<void>;

  beforeEach(async () => {
    ({ adapter, teardown } = await leg.make());
  });

  afterEach(async () => {
    await teardown();
  });

  const raw = (sql: string, params?: unknown[]) => leg.raw(adapter, sql, params);

  async function sealedChain(): Promise<string> {
    const chainId = unique('sealed');
    await adapter.storeChain(makeChain({ chainId }));
    await adapter.store(makeEnvelope({ evidenceId: unique('ev') }), chainId);
    await adapter.sealChain(chainId, '2026-04-04T11:00:00.000Z');
    return chainId;
  }

  describe('chains', () => {
    it('an UPDATE cannot reopen a sealed chain, and the chain keeps refusing appends', async () => {
      const chainId = await sealedChain();

      const message = await refusal(() =>
        raw("UPDATE chains SET status = 'active', sealed_at = NULL WHERE chain_id = ?", [chainId]),
      );
      expect(message).toMatch(/sealed/);

      const chain = await adapter.getChain(chainId);
      expect(chain?.status).toBe('sealed');
      expect(chain?.sealedAt).toBe('2026-04-04T11:00:00.000Z');
      await expect(adapter.store(makeEnvelope({ evidenceId: unique('ev'), sequenceNumber: 2 }), chainId))
        .rejects.toThrow(/sealed/i);
    });

    it('status alone cannot be flipped back either', async () => {
      const chainId = await sealedChain();
      expect(await refusal(() => raw("UPDATE chains SET status = 'active' WHERE chain_id = ?", [chainId])))
        .toMatch(/sealed/);
      expect((await adapter.getChain(chainId))?.status).toBe('sealed');
    });

    it('a seal cannot be re-dated or cleared', async () => {
      const chainId = await sealedChain();
      expect(await refusal(() =>
        raw('UPDATE chains SET sealed_at = ? WHERE chain_id = ?', ['2027-01-01T00:00:00.000Z', chainId]),
      )).toMatch(/sealed/);
      expect(await refusal(() => raw('UPDATE chains SET sealed_at = NULL WHERE chain_id = ?', [chainId])))
        .toMatch(/sealed/);
      expect((await adapter.getChain(chainId))?.sealedAt).toBe('2026-04-04T11:00:00.000Z');
    });

    it('a chains row cannot be deleted — a chain with no row is open, so a delete would reopen it', async () => {
      const chainId = await sealedChain();
      expect(await refusal(() => raw('DELETE FROM chains WHERE chain_id = ?', [chainId]))).toMatch(/chains/);
      expect((await adapter.getChain(chainId))?.status).toBe('sealed');
      await expect(adapter.store(makeEnvelope({ evidenceId: unique('ev'), sequenceNumber: 2 }), chainId))
        .rejects.toThrow(/sealed/i);
    });

    it('the identity columns are frozen, on an active chain as on a sealed one', async () => {
      const chainId = unique('active');
      await adapter.storeChain(makeChain({ chainId, parentChainId: 'parent', forkPoint: 3 }));
      const attempts: Array<[string, unknown[]]> = [
        ['UPDATE chains SET chain_id = ? WHERE chain_id = ?', [unique('renamed'), chainId]],
        ['UPDATE chains SET parent_chain_id = ? WHERE chain_id = ?', ['other-parent', chainId]],
        ['UPDATE chains SET parent_chain_id = NULL WHERE chain_id = ?', [chainId]],
        ['UPDATE chains SET fork_point = ? WHERE chain_id = ?', [9, chainId]],
        ['UPDATE chains SET created_at = ? WHERE chain_id = ?', ['2020-01-01T00:00:00.000Z', chainId]],
      ];
      for (const [sql, params] of attempts) {
        expect({ sql, message: await refusal(() => raw(sql, params)) })
          .toEqual({ sql, message: expect.stringMatching(/immutable/) });
      }
      expect(await adapter.getChain(chainId)).toEqual(makeChain({ chainId, parentChainId: 'parent', forkPoint: 3 }));
    });

    it('sealing an active chain is still the one transition the table allows', async () => {
      const chainId = unique('to-seal');
      await adapter.storeChain(makeChain({ chainId }));
      await raw("UPDATE chains SET status = 'sealed', sealed_at = ? WHERE chain_id = ?", ['2026-04-04T12:00:00.000Z', chainId]);
      expect((await adapter.getChain(chainId))?.status).toBe('sealed');
    });

    if (leg.name === 'postgres') {
      it('TRUNCATE chains is refused (row-level triggers do not fire on TRUNCATE)', async () => {
        await sealedChain();
        expect(await refusal(() => raw('TRUNCATE chains'))).toMatch(/chains/);
      });
    }
  });

  describe('chain_forks', () => {
    async function recordedFork(): Promise<{ forkId: string; oldChainId: string }> {
      const forkId = unique('fork');
      const oldChainId = unique('old');
      await adapter.storeFork({
        ...makeFork({ id: forkId, oldChainId, newChainId: unique('new'), forkAfterSequence: 3, sealedOldChainLength: 3 }),
        sealedOldChainHead: 3,
      });
      return { forkId, oldChainId };
    }

    it('the recorded sealed head cannot be lowered, cleared or deleted', async () => {
      const { forkId, oldChainId } = await recordedFork();

      expect(await refusal(() =>
        raw('UPDATE chain_forks SET sealed_old_chain_head = sealed_old_chain_head - 1 WHERE id = ?', [forkId]),
      )).toMatch(/append-only/);
      expect(await refusal(() => raw('UPDATE chain_forks SET sealed_old_chain_head = NULL WHERE id = ?', [forkId])))
        .toMatch(/append-only/);
      expect(await refusal(() => raw('UPDATE chain_forks SET sealed_old_chain_length = 2 WHERE id = ?', [forkId])))
        .toMatch(/append-only/);
      expect(await refusal(() => raw('DELETE FROM chain_forks WHERE id = ?', [forkId]))).toMatch(/append-only/);

      const fork = await adapter.getFork(forkId);
      expect(fork?.sealedOldChainHead).toBe(3);
      expect(fork?.sealedOldChainLength).toBe(3);
      // What the verifiers are handed as the sealed chain's high-water mark is
      // unchanged, so a record deleted from its tail stays a reported gap.
      expect(await chainUpperBound(adapter, oldChainId)).toBe(3);
    });

    if (leg.name === 'postgres') {
      it('TRUNCATE chain_forks is refused', async () => {
        await recordedFork();
        expect(await refusal(() => raw('TRUNCATE chain_forks'))).toMatch(/append-only/);
      });
    }
  });
});

/**
 * The remediation NoActiveChainError gives has to be one the store allows.
 * The `chains` trigger refuses a plain UPDATE that lifts a seal, so the
 * message says how the store's owner re-opens a row, and names the
 * alternative that needs no change to a row: naming the chain at init.
 */
describe('NoActiveChainError names a repair the database accepts', () => {
  const message = new NoActiveChainError([
    { chainId: 'default', status: 'sealed', createdAt: '2026-04-04T10:00:00.000Z', sealedAt: '2026-04-04T11:00:00.000Z' },
  ]).message;

  it('says a plain UPDATE is refused, and gives the SQLite and Postgres ways past it', () => {
    expect(message).not.toMatch(/re-activate the row that should still be live — then/);
    expect(message).toContain('chains_enforce_immutable');
    expect(message).toContain("session_replication_role = 'replica'");
  });

  it('offers registering a new active identity, and naming the chain with Tzun.init({ chainId })', () => {
    expect(message).toContain('storeChain()');
    expect(message).toContain('name the chain this instance writes to with Tzun.init({ chainId })');
    expect(message).not.toContain('There is no Tzun.init({ chainId }) option');
  });
});
