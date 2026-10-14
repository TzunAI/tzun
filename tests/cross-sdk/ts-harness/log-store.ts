/**
 * Cross-SDK harness for the evidence logs (Anchor §3, §4.3.2; Tree §5.2)
 * — Node side.
 *
 * Reads one JSON command from stdin and writes one JSON result on stdout,
 * like `index.ts`, against the in-repo SDK.
 *
 *   { action: "origins", ns, storeId, chainIds: string[], kinds: string[] }
 *     → { evidence: string[], storeLogs: string[] }
 *     `evidenceLogOrigin` for each chain id and `storeLogOrigin` for each kind.
 *
 *   { action: "refusals", chainIds: string[], namespaces: string[] }
 *     → { chainIds: Array<string | null>, namespaces: boolean[] }
 *     `chainIdRefusal` for each chain id (null when it names a log), and
 *     whether `assertLogNamespace` accepts each namespace.
 *
 *   { action: "create-sqlite-store", path, logNamespace? }
 *     → { storeId, ns }
 *     Opens a SQLite store at `path` through `SqliteStorageAdapter`, which
 *     creates the schema, mints the identity and installs the triggers, and
 *     closes it again.
 *
 *   { action: "postgres-ddl" }
 *     → { statements: string[] }
 *     The statements `PostgresStorageAdapter.ensureTables()` sends, in order,
 *     to a connection that records them and answers each with no rows. No
 *     database is involved.
 */
import { PostgresStorageAdapter } from '../../../src/storage/postgres';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { assertLogNamespace, chainIdRefusal, evidenceLogOrigin, storeLogOrigin } from '../../../src/storage/log-store';

interface Command {
  action: 'origins' | 'refusals' | 'create-sqlite-store' | 'postgres-ddl';
  ns?: string;
  storeId?: string;
  chainIds?: string[];
  namespaces?: string[];
  kinds?: string[];
  path?: string;
  logNamespace?: string;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
  });
}

async function main(): Promise<void> {
  const cmd = JSON.parse(await readStdin()) as Command;
  if (cmd.action === 'origins') {
    const ns = cmd.ns!;
    const storeId = cmd.storeId!;
    process.stdout.write(
      JSON.stringify({
        evidence: (cmd.chainIds ?? []).map((chainId) => evidenceLogOrigin(ns, storeId, chainId)),
        storeLogs: (cmd.kinds ?? []).map((kind) => storeLogOrigin(ns, storeId, kind)),
      }),
    );
    return;
  }
  if (cmd.action === 'refusals') {
    const accepts = (ns: string): boolean => {
      try {
        assertLogNamespace(ns);
        return true;
      } catch {
        return false;
      }
    };
    process.stdout.write(
      JSON.stringify({
        chainIds: (cmd.chainIds ?? []).map((chainId) => chainIdRefusal(chainId)),
        namespaces: (cmd.namespaces ?? []).map(accepts),
      }),
    );
    return;
  }
  if (cmd.action === 'create-sqlite-store') {
    if (!cmd.path) throw new Error('create-sqlite-store: path required');
    const adapter = new SqliteStorageAdapter(
      cmd.path,
      cmd.logNamespace === undefined ? {} : { logNamespace: cmd.logNamespace },
    );
    const identity = await adapter.logStore().getStoreIdentity();
    await adapter.close();
    process.stdout.write(JSON.stringify({ storeId: identity.storeId, ns: identity.ns }));
    return;
  }
  if (cmd.action === 'postgres-ddl') {
    const statements: string[] = [];
    const client = {
      query: async (sql: string) => {
        statements.push(sql);
        return { rows: [], rowCount: 0 };
      },
      release: () => undefined,
    };
    const adapter = new PostgresStorageAdapter('postgres://unused/unused');
    // The adapter's pool, replaced before it has made a connection: the one
    // `ensureTables()` takes is the recording client above.
    const unused = (adapter as unknown as { pool: { end(): Promise<void> } }).pool;
    (adapter as unknown as { pool: unknown }).pool = { connect: async () => client, query: client.query, end: async () => undefined };
    await adapter.ensureTables();
    await unused.end();
    process.stdout.write(JSON.stringify({ statements }));
    return;
  }
  throw new Error(`unknown action ${JSON.stringify((cmd as { action?: unknown }).action)}`);
}

main().catch((err: unknown) => {
  process.stderr.write(String(err instanceof Error ? err.stack ?? err.message : err));
  process.exit(1);
});
