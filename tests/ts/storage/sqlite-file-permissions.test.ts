/**
 * The SQLite evidence store and its sidecars are owner-only (0600), whatever
 * the process umask.
 *
 * Created with the process umask, under the usual 022/002 umask ./tzun.db —
 * the default persistent backend the SDK picks with no configuration — would
 * sit at mode 0644, world-readable. The envelopes it holds carry aiOutput,
 * humanReason, WebAuthn assertions and custody actors, so any other local
 * account on a shared CI box or container volume could read the whole decision
 * history. The -wal/-shm sidecars created by `journal_mode = WAL` carry the
 * most recent writes and need the same mode.
 *
 * These tests assert the OUTCOME (owner-only modes on disk), not the mechanism,
 * so they keep holding if the umask narrowing is later replaced by chmod or
 * vice versa.
 */
import { chmodSync, existsSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';

function mode(p: string): number {
  return statSync(p).mode & 0o777;
}

describe('SqliteStorageAdapter file permissions', () => {
  let dir: string;
  let previousUmask: number;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-sqlite-perms-'));
    // The hostile-but-ordinary condition: a permissive umask, under which an
    // adapter that relied on the umask would emit world-readable files.
    previousUmask = process.umask(0o000);
  });

  afterEach(() => {
    process.umask(previousUmask);
    rmSync(dir, { recursive: true, force: true });
  });

  it('creates the database file owner-readable only under a permissive umask', async () => {
    const dbPath = join(dir, 'tzun.db');
    const adapter = new SqliteStorageAdapter(dbPath);
    try {
      expect(mode(dbPath)).toBe(0o600);
    } finally {
      await adapter.close();
    }
  });

  it('leaves the WAL and SHM sidecars owner-readable only', async () => {
    const dbPath = join(dir, 'tzun.db');
    const adapter = new SqliteStorageAdapter(dbPath);
    try {
      // WAL mode materialises the sidecars; assert on whichever exist so the
      // test is not vacuous on a platform that defers one of them.
      const sidecars = [`${dbPath}-wal`, `${dbPath}-shm`].filter((p) => existsSync(p));
      expect(sidecars.length).toBeGreaterThan(0);
      for (const p of sidecars) {
        expect({ path: p, mode: mode(p).toString(8) }).toEqual({
          path: p,
          mode: '600',
        });
      }
    } finally {
      await adapter.close();
    }
  });

  it('narrows an existing world-readable database on open', async () => {
    const dbPath = join(dir, 'legacy.db');
    // A database left behind by an older SDK build, already 0644.
    writeFileSync(dbPath, '');
    chmodSync(dbPath, 0o644);
    expect(mode(dbPath)).toBe(0o644);

    const adapter = new SqliteStorageAdapter(dbPath);
    try {
      expect(mode(dbPath)).toBe(0o600);
    } finally {
      await adapter.close();
    }
  });

  it('restores the process umask after construction', async () => {
    const dbPath = join(dir, 'umask.db');
    const before = process.umask(0o022);
    const adapter = new SqliteStorageAdapter(dbPath);
    const after = process.umask(before);
    try {
      expect(after).toBe(0o022);
    } finally {
      await adapter.close();
    }
  });

  it('opens an in-memory database without touching the filesystem', async () => {
    // `:memory:` has no file to chmod; the guard must not throw.
    const adapter = new SqliteStorageAdapter(':memory:');
    await expect(adapter.close()).resolves.toBeUndefined();
  });
});
