/**
 * A process that dies in the middle of the evidence-log migration
 * (Tree §5.2), for `log-storage-upgrade.test.ts`.
 *
 *   tsx tests/ts/helpers/migration-crash-child.ts sqlite <file>
 *   tsx tests/ts/helpers/migration-crash-child.ts postgres <url>
 *
 * It opens the store, which runs the migration, and SIGKILLs itself once the
 * backfill is written and before any trigger exists: no finally block, no
 * ROLLBACK, no clean close. What the store holds afterwards is what a crash
 * leaves behind.
 */
import { logMigrationTestHooks } from '../../../src/storage/log-store';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';

async function main(): Promise<void> {
  const [backend, location] = process.argv.slice(2);
  logMigrationTestHooks.afterBackfill = () => {
    process.stdout.write('backfilled\n');
    process.kill(process.pid, 'SIGKILL');
  };
  if (backend === 'sqlite') {
    new SqliteStorageAdapter(location);
  } else if (backend === 'postgres') {
    await new PostgresStorageAdapter(location).ensureTables();
  } else {
    throw new Error(`unknown backend ${backend}`);
  }
  process.stdout.write('migration finished without the hook\n');
}

main().catch((err: unknown) => {
  process.stderr.write(String(err instanceof Error ? err.stack ?? err.message : err));
  process.exit(1);
});
