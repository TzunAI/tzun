# tzun-sdk (Python)

Forensic evidence infrastructure for AI decisions — Python edition.

`tzun-sdk` is the Python port of the TypeScript SDK, `@tzun/sdk`.
Both SDKs speak the same v1 canonical wire format byte-for-byte: a decision
captured in TypeScript verifies in Python and vice versa.

## Extras

The package is not on PyPI, and no licence to use it is granted
([License](#license)). Pilots receive it under a written agreement. Its
optional extras:

| Extra | Adds |
|---|---|
| `postgres` | `PostgresAdapter` (asyncpg, psycopg, psycopg_pool) |
| `sqlite` | `SqliteAdapter` (aiosqlite) |
| `anchor` | EVM anchor verification (coincurve, pycryptodomex) |
| `all` | every extra |

One further extra exists, and nothing in this release needs it: `[rfc3161]`
installs `rfc3161-client`, but RFC 3161 timestamping (`RFC3161Backend`) is
part of the core install and uses no RFC 3161 library.

Python 3.11+ required.

## The API

`MemoryAdapter` needs no extra; swap in `SqliteAdapter` (`[sqlite]`) or
`PostgresAdapter` (`[postgres]`) to keep the evidence.

```python
import asyncio
import tzun_sdk
from tzun_sdk.contributions import single_model
from tzun_sdk.storage import MemoryAdapter


async def main() -> None:
    async with await tzun_sdk.Tzun.init(storage=MemoryAdapter()) as tzun:
        # 1. Build an AI-BOM from any vendor (request, response) pair.
        ai_bom = await tzun_sdk.hook(
            "openai",
            {"temperature": 0.7},
            {"model": "gpt-4o-2024-08-06"},
            tzun=tzun,
        )

        # 2. Capture the decision: who decided, and the model that contributed.
        result = await tzun.capture(
            ai_output={"score": 0.87, "label": "approve"},
            action="approved",
            reason="risk threshold met",
            decider={"kind": "human", "id": "acct:u-4821"},
            contributions=single_model(ai_bom),
        )

        # 3. Verify.
        v = await tzun.verify(result.evidenceId)
        assert v.valid


asyncio.run(main())
```

## Public API

- `Tzun` / `TzunSync` — async and sync clients (Tzun.init / TzunSync.init).
- `hook(vendor, request, response, *, tzun=None)` — extract an AI-BOM
  from any of 6 supported vendors (openai, anthropic, bedrock, vertex,
  azure_ai, openrouter). Pure function; no client wrapping.
  `openrouter` covers every model the OpenRouter gateway serves: the record
  names OpenRouter as the vendor that served the call, the id it served
  (`response.model`, variant suffix included), the maker as the id's author
  prefix (`trainedBy`), the upstream provider OpenRouter reports
  (`infrastructure.provider`), and, when the request carries an
  `openrouter_endpoint` hint, the gateway URL called
  (`infrastructure.endpoint`). The integrity tier is `vendor-asserted`, the
  gateway being the asserting vendor.
- `attach(client, *, tzun)` — optional sugar wrapping a vendor client so
  per-call `tzun_capture=DecisionInput(...)` triggers `hook() + capture()`
  automatically. Kwarg-absent calls pass through with zero overhead. An
  OpenAI client whose `base_url` host is `openrouter.ai` is detected as
  `openrouter`, and its base URL is recorded as the endpoint; pass
  `vendor="openai"` to keep the openai classification, or
  `vendor="openrouter"` for a client that reaches OpenRouter through another
  host. The `openrouter` vendor intercepts the same two methods as `openai`:
  `chat.completions.create` and `responses.create`.
- `tzun.agents`, `tzun.links`, `tzun.deciders`, `tzun.decision_graph`,
  `tzun.mandates` — the agent catalog, links between records and link
  records, decider commitment openings, the bounded walk over a record's
  links, and mandates (an agent deciding under a principal's signed mandate).
- `storage.{MemoryAdapter, SqliteAdapter, PostgresAdapter, HttpBackendAdapter}`
  — `SqliteAdapter` needs the `[sqlite]` extra and `PostgresAdapter` the
  `[postgres]` extra.
- `models.{EvidenceEnvelope, EvidencePayload, AiBom, ModelDescriptor, DecisionInput, ...}`
  — Pydantic v2 models.
- `errors.{TzunError, VerificationError, TamperDetected, ...}` — typed
  exception hierarchy.

## CLI

The CLI's default store is `memory://`, which keeps nothing between commands;
point it at a SQLite file (needs the `[sqlite]` extra) with
`TZUN_STORAGE_URI` or the global `--storage` option.

```bash
export TZUN_STORAGE_URI=sqlite:evidence.db
tzun --help
tzun capture --ai-output payload.json --action approved --reason ok --decider acct:u-4821
tzun verify <evidence-id>
tzun verify-range --from 1 --to 10
tzun models register --from-file descriptor.json
tzun models show <digest>
tzun models compute-digest <weights-path>
```

## Cross-SDK parity

The Python SDK is byte-identical to the TypeScript SDK on the canonical
wire format. Every entry in `vectors/v1.0-canonical-vectors.json`
roundtrips byte-identically through both SDKs; cross-SDK tests in
`tests/cross-sdk/` exercise this on every pull request. The record rules
(decider, contributions, links, mandates, agent descriptors) are held to the
TypeScript engine's answers on about twelve thousand cases in
`python/tests/parity/` (see `oracle_cases.py` there to regenerate them). All
of these paths are in the [source repository](https://github.com/TzunAI/tzun).

## Status

Pre-1.0. `tzun-sdk` and the TypeScript packages (`@tzun/sdk`, `@tzun/engine`)
are released together and carry the same version number. A minor release may
change the API; the [changelog](https://github.com/TzunAI/tzun/blob/main/CHANGELOG.md)
says what each one changed, and the
[migration notes](https://github.com/TzunAI/tzun/blob/main/python/MIGRATION.md)
cover the 0.8.0 record, storage backends and running both SDKs side by side.
A record captured by one SDK verifies in the other because both implement the
v1 canonical wire format (`schemaVersion` `v1.0`), which is specified at
[spec.tzun.ai](https://spec.tzun.ai).

## License

No licence is granted. The source is published so that it can be read: see
[LICENSE.md](https://github.com/TzunAI/tzun/blob/main/LICENSE.md) and
[NOTICE](https://github.com/TzunAI/tzun/blob/main/NOTICE). The package is not
on PyPI. The conformance vectors in the repository's `vectors/` directory are
CC0-1.0. For a licence, contact licensing@tzun.ai.

## Links

- Source: https://github.com/TzunAI/tzun (the Python package is in `python/`)
- Issues: https://github.com/TzunAI/tzun/issues
- Security policy: https://github.com/TzunAI/tzun/blob/main/SECURITY.md
- Changelog: https://github.com/TzunAI/tzun/blob/main/CHANGELOG.md
- Specification: https://spec.tzun.ai
