# Support

## Where to ask

| What you have | Where it goes |
|---|---|
| A security or evidence-integrity vulnerability | **Private advisory** — see [`SECURITY.md`](./SECURITY.md). Never a public issue. |
| A reproducible bug | [Open an issue](https://github.com/TzunAI/tzun/issues/new/choose) with the bug template |
| A feature or API request | [Open an issue](https://github.com/TzunAI/tzun/issues/new/choose) with the feature template |
| "How do I…", design questions, integration advice | [Discussions](https://github.com/TzunAI/tzun/discussions) |
| Licensing enquiries | licensing@tzun.ai; [`LICENSE.md`](./LICENSE.md) states that no licence is granted |
| Commercial or pilot enquiries | hello@tzun.ai |

## Before you file a bug

Please include the package versions (`@tzun/sdk` and `@tzun/engine`, which
should match, or `tzun-sdk` for Python), the mode (`dev`, `local`, `cloud`,
`self-hosted`) and the storage (in-memory, SQLite, Postgres), the runtime and
its version, and a minimal reproduction. For anything involving verification,
include the envelope (with any sensitive payload fields redacted) and what you
expected `verify()` to return.

## What is supported

Pre-1.0, only the latest minor is supported, and fixes, security fixes
included, land there. [`SECURITY.md`](./SECURITY.md) lists the supported
versions.
