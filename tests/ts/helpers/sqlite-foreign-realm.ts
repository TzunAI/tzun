/**
 * Put a test file in the state every jest worker puts most of its files in:
 * better-sqlite3 raises its errors from another realm.
 *
 * The native addon is loaded once per process, and the first `new Database()`
 * in the process hands it that file's `SqliteError` constructor
 * (`addon.setErrorConstructor`, guarded by `addon.isInitialized`). Each test
 * file runs in a vm context of its own, so in every later file of the same
 * worker a driver error's prototype chain ends in another context's `Error`:
 * `err instanceof Error` is false, and since `SqliteError` is built with
 * `Error.call(this)` the error has no [[ErrorData]] slot and its toString tag
 * is `[object Object]`. Jest's `rejects.toThrow` then reports "Received
 * function did not throw" for a statement the database refused. Which files
 * meet this depends on which file each worker happens to run first, so such
 * an assertion passes when its file runs alone and fails in some full runs.
 *
 * `raiseSqliteErrorsFromAnotherRealm()` hands the addon a `SqliteError` built
 * in a fresh vm context, whichever file the worker ran first, and checks that
 * a refused statement then raises an error that is not an `instanceof Error`
 * here. A file that calls it in `beforeAll` meets the cross-realm error on
 * every run. The function it returns hands the addon this file's own
 * `SqliteError`, the state the addon is in after any file that opened a
 * database first.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runInNewContext } from 'node:vm';
import Database from 'better-sqlite3';

interface BetterSqlite3Addon {
  setErrorConstructor(ctor: unknown): void;
  isInitialized?: boolean;
}

export function raiseSqliteErrorsFromAnotherRealm(): () => void {
  const root = dirname(require.resolve('better-sqlite3/package.json'));
  // The module better-sqlite3's own `bindings('better_sqlite3.node')` loads:
  // Node keeps one instance of a native module per process.
  const addon = require(join(root, 'build', 'Release', 'better_sqlite3.node')) as BetterSqlite3Addon;

  // better-sqlite3's own SqliteError, evaluated in a context of its own.
  const sandbox = { module: { exports: undefined as unknown } };
  runInNewContext(readFileSync(join(root, 'lib', 'sqlite-error.js'), 'utf8'), sandbox, {
    filename: 'better-sqlite3/lib/sqlite-error.js (another realm)',
  });
  addon.setErrorConstructor(sandbox.module.exports);
  addon.isInitialized = true;

  const probe = new Database(':memory:');
  let raised: unknown;
  try {
    probe.exec('SELECT * FROM no_such_table');
  } catch (err) {
    raised = err;
  } finally {
    probe.close();
  }
  if (raised === undefined) throw new Error('the probe statement was not refused');
  if (raised instanceof Error) {
    throw new Error('better-sqlite3 still raises errors from this realm: the addon did not take the other SqliteError');
  }

  return () => addon.setErrorConstructor(Database.SqliteError);
}
