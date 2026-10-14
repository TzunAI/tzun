# Contributing to Tzun

Thanks for your interest. Tzun is a cryptographic evidence layer: it records
what a human decided about an AI recommendation, in a form a third party can
check later. That purpose sets the bar for changes — a patch that makes the
system *report* success without *performing* the check it names is the one class
of bug we care most about avoiding.

**Outside contributions are not accepted.** No licence to this code is granted
(see [`LICENSE.md`](./LICENSE.md)), and we do not take pull requests from
outside Tzun. Issues are welcome: bug reports, design questions and feature
requests (see [`SUPPORT.md`](./SUPPORT.md)). The rest of this file is how
Tzun's maintainers build, test and change the repository.

Please read [`SECURITY.md`](./SECURITY.md) before filing anything that could be
a vulnerability. Do not open a public issue for those.

## Getting set up

This is a **pnpm workspace** (Node.js 22 or later, pnpm 9). `npm install` will
not work — the root package depends on the engine via the `workspace:` protocol.

```bash
corepack enable                                   # or install pnpm 9 another way
pnpm install
pnpm --filter @tzun/engine build                  # required before SDK build/test
pnpm test                                         # TypeScript suite (jest)
```

Python SDK (Python 3.11 or later):

```bash
cd python
python -m venv .venv && . .venv/bin/activate
pip install --upgrade pip                         # pip 25.1 or later reads --group
pip install -e '.[all]' --group dev
pytest
```

A local Postgres for the live-DB tests:

```bash
pnpm run dev:db          # publishes on host port 55432 (not 5432)
pnpm run dev:db:stop
```

If a live-DB test fails with `ECONNREFUSED 127.0.0.1:55432` you are probably
inside a container — use `host.docker.internal` in the connection string.

## The rules that matter here

**1. The hashed field set is a contract.** `action, aiOutput, aiSystemId,
capturedAt, contributions, decider, evidenceId, links, reason, sequenceNumber,
signoffExpectation` are what the digest covers. Changing that set, the canonicalization rules, or number/string
formatting changes every digest that will ever be computed — and invalidates
every digest already computed. Record format v1.0 is not yet frozen
([Specs §2](https://spec.tzun.ai/#s2)). While it is not, a change to the hashed field
set can be made under the same `v1.0` tag, as a breaking change: stores from
earlier releases are refused, and the release notes say how to rebuild. A
change to the canonicalization rules or number/string formatting needs a new
schema version and a migration story, not a patch, as does any change to the
set once v1.0 is frozen. Either way, say so explicitly in the PR.

**2. TypeScript and Python must agree byte for byte.** Any change to
canonicalization, digests or the wire types must land in both implementations in
the same PR, with a conformance vector added to `vectors/` that would fail
before the change. The cross-SDK parity job is not optional.

**3. A verifier may not report success it did not establish.** If a check cannot
be performed — unknown schema version, missing predecessor, unparseable token —
the result is a failure or an explicit "unknown", never a pass. Presence of an
artifact is not verification of it.

**4. Append-only means append-only.** No update or delete paths on evidence
beyond the narrow, documented exceptions (attestation results and recovery
links), and those must be justified in the PR.

**5. Ordering is part of the threat model.** Anything that reads a chain head,
reserves a sequence number, or awaits between the two needs to be correct when
two callers do it at once. Add the concurrent test.

## Tests

Every behavioural change ships with a test that **fails before and passes
after**. If your change fixes a bug that an existing test asserted as correct,
**invert that test — do not delete it**, and mention it in the PR body. Tests
that pin bugs are how the same defect comes back.

For anything security- or integrity-related, add the negative case: the forged
token, the duplicate sequence, the nulled link, the wrong-chain predecessor.

The Postgres cases run when `RUN_INTEGRATION_TESTS=true` and `DATABASE_URL` is
set, and `DATABASE_URL` must name a throwaway database whose name ends in
`_test`; any other name is refused. Each suite gets a schema of its own from
`tests/ts/helpers/postgres-test-db.ts`, so one database serves a full parallel
run. A new Postgres suite takes its URL from that helper rather than reading
`DATABASE_URL` itself.

## Commits and pull requests

- Conventional-commit prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
  `chore:`, `build:`, `ci:`, `perf:`. Add `!` or a `BREAKING CHANGE:` footer for
  anything that changes a digest, a wire type or a published API.
- Explain *why*, not just what. If you considered another approach and rejected
  it, that sentence is worth more than a summary of the diff.
- Keep PRs to one concern. A drive-by refactor inside a security fix makes the
  fix hard to review and hard to revert.
- CI must be green: lint, typecheck, both test suites, the cross-SDK parity
  job, the codegen drift guard, the public hygiene check, and, when your change
  touches what they cover, the Go stock-library gate on the Merkle vectors and
  the anchoring suite against a local EVM node (`pnpm run test:anvil`, which
  needs Docker).
- Pull request titles and bodies, commit messages and files refer only to this
  repository and public places: `scripts/check-public-hygiene.sh` states the
  rules, and CI runs it.

## Releases

Publishing is off: `package.json` and `packages/engine/package.json` set
`"private": true`, `python/pyproject.toml` carries the classifier
`Private :: Do Not Upload`, and release.yml and python-publish.yml stop while
any of the three does. While one does, auto-release.yml creates no tag.

Maintainers cut releases. Once publishing is on, merging a version bump to
main publishes it. `@tzun/sdk`, `@tzun/engine` and `tzun-sdk` version **in
lockstep**: CI refuses the three versions drifting apart, and a change to
`src/` or `packages/engine/src/` that does not bump them. A maintainer cuts a
release like this:

1. Bump `version` in `package.json`, `packages/engine/package.json` and
   `python/pyproject.toml`.
2. Move the `[Unreleased]` entries of `CHANGELOG.md` under a
   `## [<version>] — YYYY-MM-DD` heading.
3. Merge to main. Once publishing is on, merging a version bump to main
   publishes it, and the CHANGELOG section is the release note.

## Questions

Open a [Discussion](https://github.com/TzunAI/tzun/discussions) for design
questions and "how do I…"; open an Issue for a specific defect or request.
