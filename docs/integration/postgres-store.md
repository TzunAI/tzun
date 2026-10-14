# Running a store on Postgres

`Tzun.init({ dbUrl })` keeps its store in the connection's current schema
(`current_schema()`, the first schema on its `search_path` that exists).
`ensureTables()` creates the tables there and installs the triggers that keep them append-only,
and it runs on every open: every function is `CREATE OR REPLACE`, so a store
written by an earlier SDK gets the current guards the next time it is opened.

## What the guards stop, and what they do not

The triggers stop a least-privileged role: one granted `SELECT`, `INSERT` and
the `UPDATE`s the SDK makes (attestation retry, custody appends, recovery
relinks, anchor fills), and nothing else. Such a role cannot rewrite a record,
delete one, truncate a table, write a custody entry whose hash does not
recompute, or plant a row ahead of the rows it follows.

They do not stop the table owner or a superuser, who can disable any trigger
(`ALTER TABLE … DISABLE TRIGGER`, `session_replication_role = 'replica'`). The
boundary against the owner is the chain digest and the external attestation:
tampering by the owner is detectable, not preventable.

## The anchoring tables need the store's owner

Every insert into or update of the anchoring tables (`log_checkpoints`,
`anchor_publications`, `anchor_wallets`, `anchor_wallet_txs`, `anchor_lease`, a
per-store log or its leaves), every delete of the lease, and every update that
adds, replaces or removes a record's `nonRepudiation.anchor` needs the role that
owns the store, judged by `session_user`: the owner itself, or a
role that can act as it (from PostgreSQL 16, one that holds it with `INHERIT`
or `SET`; before 16, any member). Any other role is refused with
`[tzun:anchoring_owner_required]`, SQLSTATE `42501`, even through a
`SECURITY DEFINER` function the owner wrote. An update that leaves a record's
anchor as it is (an attestation retry, a custody append) is not gated. The
other anchoring tables refuse deletes to every role through their own guards. A capture role still writes
evidence logs and their leaves, which the store binds to its records: an
evidence leaf must copy the record stored at its position.

This keeps every role but the SDK's own (an ETL job, a reporting tool, a second
service on the database) from stopping the store's anchoring: one anchor-log
leaf the scheduler cannot explain stops it for good. It does nothing against
the owner. Against the owner, and against every writer of a SQLite file, the
defence is the scheduler's: it signs only what it re-derives from the logs, and
accepts an earlier publication as its own only by its signed transaction and a
sender its configuration or manifest names. Run every process that opens the
store on 0.8.0 or later: a scheduler of an earlier release cannot take the
lease of a store a 0.8.0 process has opened.

## Name resolution

A Postgres trigger function runs with the `search_path` of the session whose
statement fired it. A function that names a table bare reads whatever that
session resolves the name to, and a session can put a table of its own ahead
of the store's: a temporary table of the same name (temporary tables are
searched first unless the path says otherwise), or a table in a schema it can
create in and puts first.

Every function the SDK creates runs with `SET search_path = pg_catalog, pg_temp`
and names each table it reads or writes, and each function of the store's it
calls, through the schema of the table its trigger is on (`TG_TABLE_SCHEMA`),
in a statement it runs with `EXECUTE format('%I.…')`. A temporary table, or a
table, function or operator in a schema the inserting session puts first,
does not stand in for the store's.

Every process that opens the store must run this version or later: an
earlier SDK's `ensureTables()` replaces these functions with its own, unpinned
ones.

## Deployment requirements

The role the SDK connects as runs `ensureTables()` on every open, so it owns
the store's tables and functions and needs `CREATE` on the store's schema.
The triggers do not bind it (see above). Give it a `search_path` that holds
the store's schema and nothing another role can create in.

For every other role that writes the store:

1. **No temporary tables.** Every role holds `TEMPORARY` on a database through
   `PUBLIC` unless it is revoked:

   ```sql
   REVOKE TEMPORARY ON DATABASE <database> FROM PUBLIC;
   REVOKE TEMPORARY ON DATABASE <database> FROM <role>;  -- if granted directly
   ```

2. **No `CREATE` on the store's schema, or on any schema in the SDK role's
   `search_path`.** The adapter's own statements name tables bare and resolve
   through that path. Before PostgreSQL 15, `PUBLIC` holds `CREATE` on the
   `public` schema:

   ```sql
   REVOKE CREATE ON SCHEMA public FROM PUBLIC;
   REVOKE CREATE ON SCHEMA <store schema> FROM <role>;
   ```

   The default path starts with `"$user"`: if a schema named after the SDK's
   role exists, it is searched first, and no other role may create in it
   either.

The SDK's functions depend on neither: they read nothing through the
session's names. The requirements protect what does:

- The statements the adapter sends from the application. They name the
  store's tables bare and resolve through the SDK role's `search_path`, so a
  table another role creates in a schema on that path stands in for the
  store's (requirement 2). A temporary table is visible only to the session
  that created it, and the SDK creates none.
- Functions an earlier SDK installed, until the next open by this version,
  and any function that restates these guards in a store kept outside the SDK
  (see [anchor-store.md](./anchor-store.md)). These read through the firing
  session's names, and that session chooses its own `search_path`: they hold
  only against a role with no temporary tables and no `CREATE` on any schema.
- Any SQL other services run against the store, which resolves through their
  own sessions' paths.

To check a role:

```sql
SELECT has_database_privilege('<role>', current_database(), 'TEMPORARY');  -- false
SELECT nspname FROM pg_namespace
 WHERE has_schema_privilege('<role>', oid, 'CREATE');  -- not the store's schema, none on the SDK role's path
```
