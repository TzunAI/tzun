#!/usr/bin/env bash
# The packed packages type-check in strict consumer projects: the
# declarations @tzun/engine and @tzun/sdk ship compile in a project that
# installs nothing but the two tarballs, typescript and @types/node, and in
# one that also brings its own @types/pg and @types/better-sqlite3 at the
# oldest versions the SDK supports.
#
#   scripts/check-packed-types.sh [--no-build]
#
# Builds the engine and the SDK (--no-build skips that and packs what an
# earlier build left in dist/, as ci.yml does after its own build steps),
# packs each with pnpm as release.yml does, installs both tarballs with npm
# into two empty projects, and compiles a file in each with
#
#   tsc --strict --noEmit --module nodenext --moduleResolution nodenext
#
# skipLibCheck stays off, so every declaration file the consumer's imports
# reach is checked.
#
# The minimal consumer installs nothing else and imports both packages. A
# public type that comes from a package the consumer does not get as a
# dependency (a dev dependency's @types package, say) fails here as TS7016,
# where the repository's own build, which has every dev dependency installed
# and sets skipLibCheck, passes.
#
# The floor consumer also installs @types/pg and @types/better-sqlite3 at the
# versions below, implements a PostgresStorageExtension and a
# SqliteStorageExtension with its own PoolClient and Database, assigns the
# pool the SDK hands its extension to its own Pool, and passes its own client
# and database to an extension the SDK exports. When the SDK's range for
# either package does not accept the consumer's version, npm installs a
# second copy under @tzun/sdk, the SDK's declarations use that copy, and the
# consumer's own types no longer fit the SDK's (TS2322, TS2345, TS2719). A
# range raised above these floors fails here.
#
# Only declarations reachable from the two packages' entry points are
# checked. @tzun/sdk has no exports map, so any file under dist/ can be
# deep-imported; ten declaration files under dist/src/api and
# dist/src/benchmark import express, whose types are a dev dependency, and no
# entry point reaches them (TzunAI/tzun#12).
#
# Each npm install resolves the tarballs' dependency ranges against the live
# registry, with no lockfile and nothing pinned beyond the versions named
# here, on purpose: that is what a consumer installing the packages gets.
#
# The compiler is the TypeScript version the workspace builds with. npm runs
# no install scripts: nothing is executed, so no native module is built. Needs
# pnpm, npm and the npm registry. Exit status: 0 when both consumers compile,
# 2 on a usage error, non-zero otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

# The oldest @types/pg and @types/better-sqlite3 the SDK supports: the lower
# bounds of its ranges for them in package.json.
pg_types_floor=8.11.0
sqlite_types_floor=7.6.0

build=1
if [[ $# -gt 0 ]]; then
  if [[ $# -ne 1 || $1 != --no-build ]]; then
    echo "usage: scripts/check-packed-types.sh [--no-build]" >&2
    exit 2
  fi
  build=0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/pack" "$work/minimal" "$work/floor"

if [[ $build -eq 1 ]]; then
  pnpm --filter @tzun/engine build
  pnpm run build
fi

# pnpm pack, never npm pack: pnpm rewrites the SDK's `workspace:*` dependency
# on the engine to the engine's exact version, as it does at release. Each
# prints every file it packs; release.yml lists the tarballs, so not here.
(cd packages/engine && pnpm pack --pack-destination "$work/pack" >/dev/null)
pnpm pack --pack-destination "$work/pack" >/dev/null

typescript="$(node -p "require('typescript/package.json').version")"

# consumer <name> <description> [<package>...]: installs the two tarballs,
# TypeScript, @types/node and the packages given into $work/<name>, then
# compiles $work/<name>/consumer.ts.
consumer() {
  local name="$1" description="$2"
  shift 2
  printf '{ "name": "packed-types-%s", "private": true }\n' "$name" > "$work/$name/package.json"
  # The caller tests this function's status, which turns off set -e inside
  # it, so the steps are chained with &&.
  (
    cd "$work/$name" &&
      npm install --ignore-scripts --no-audit --no-fund --loglevel=error \
        "$work"/pack/*.tgz "typescript@$typescript" "@types/node@22" "$@" &&
      ./node_modules/.bin/tsc --strict --noEmit --module nodenext --moduleResolution nodenext consumer.ts
  ) || {
    echo "packed types: $description does not compile" >&2
    return 1
  }
  echo "packed types: $description compiles (TypeScript $typescript)" >&2
}

cat > "$work/minimal/consumer.ts" <<'TS'
// Both entry points, imported as a consumer imports them. tsc checks every
// declaration file these two imports reach.
import * as engine from '@tzun/engine';
import * as sdk from '@tzun/sdk';

export const packages = { engine, sdk };
TS

cat > "$work/floor/consumer.ts" <<'TS'
// A consumer with its own pg and better-sqlite3 types, passing its values to
// the SDK's declarations and taking the SDK's values as its own types.
import type Database from 'better-sqlite3';
import type { Pool, PoolClient } from 'pg';
import {
  decidersExtension,
  type PostgresStorageExtension,
  type SqliteStorageExtension,
} from '@tzun/sdk';

export const postgres: PostgresStorageExtension = {
  async migrate(client: PoolClient): Promise<void> {
    await client.query('SELECT 1');
  },
  methods(db) {
    const pool: Pool = db.pool;
    void pool;
    return {};
  },
};

export const sqlite: SqliteStorageExtension = {
  migrate(db: Database.Database): void {
    db.exec('SELECT 1');
  },
};

export async function migrateDeciders(client: PoolClient, db: Database.Database): Promise<void> {
  await decidersExtension.postgres?.migrate(client);
  decidersExtension.sqlite?.migrate(db);
}
TS

status=0
consumer minimal "a strict consumer of the packed @tzun/engine and @tzun/sdk" || status=1
consumer floor "a strict consumer with @types/pg@$pg_types_floor and @types/better-sqlite3@$sqlite_types_floor" \
  "@types/pg@$pg_types_floor" "@types/better-sqlite3@$sqlite_types_floor" || status=1
exit "$status"
