#!/usr/bin/env bash
# The packed packages type-check in a strict consumer project: the
# declarations @tzun/engine and @tzun/sdk ship compile in a project that
# installs nothing but the two tarballs, typescript and @types/node.
#
#   scripts/check-packed-types.sh
#
# Builds the engine and the SDK, packs each with pnpm as release.yml does,
# installs both tarballs with npm into an empty project, and compiles a file
# that imports both packages with
#
#   tsc --strict --noEmit --module nodenext --moduleResolution nodenext
#
# skipLibCheck stays off, so every declaration file the two entry points reach
# is checked. A public type that comes from a package the consumer does not
# get as a dependency (a dev dependency's @types package, say) fails here as
# TS7016, where the repository's own build, which has every dev dependency
# installed and sets skipLibCheck, passes.
#
# The compiler is the TypeScript version the workspace builds with. npm runs
# no install scripts: nothing is executed, so no native module is built. Needs
# pnpm, npm and the npm registry. Exit status: 0 when the consumer compiles,
# non-zero otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/pack" "$work/consumer"

pnpm --filter @tzun/engine build
pnpm run build

# pnpm pack, never npm pack: pnpm rewrites the SDK's `workspace:*` dependency
# on the engine to the engine's exact version, as it does at release. Each
# prints every file it packs; release.yml lists the tarballs, so not here.
(cd packages/engine && pnpm pack --pack-destination "$work/pack" >/dev/null)
pnpm pack --pack-destination "$work/pack" >/dev/null

typescript="$(node -p "require('typescript/package.json').version")"

cd "$work/consumer"
printf '{ "name": "packed-types-consumer", "private": true }\n' > package.json
cat > consumer.ts <<'TS'
// Both entry points, imported as a consumer imports them. tsc checks every
// declaration file these two imports reach.
import * as engine from '@tzun/engine';
import * as sdk from '@tzun/sdk';

export const packages = { engine, sdk };
TS

npm install --ignore-scripts --no-audit --no-fund --loglevel=error \
  "$work"/pack/*.tgz "typescript@$typescript" "@types/node@22"

if ! ./node_modules/.bin/tsc --strict --noEmit --module nodenext --moduleResolution nodenext consumer.ts; then
  echo "packed types: a strict consumer of the packed @tzun/engine and @tzun/sdk does not compile" >&2
  exit 1
fi
echo "packed types: a strict consumer of the packed @tzun/engine and @tzun/sdk compiles (TypeScript $typescript)" >&2
