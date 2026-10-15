# Migration notes

## The 0.8.0 record

The v1.0 record was revised in place: same `schemaVersion`, a new hashed
field set. Both SDKs write and verify it alike; `vectors/v1.0-worked-example-vectors.json`
and `python/tests/parity/engine-oracle.json.gz` hold Python to the TypeScript
engine byte for byte.

**Capture.** The keyword arguments changed, and the old ones raise
`TypeError`:

| Before | Now |
|---|---|
| `human_action=` | `action=` |
| `human_reason=` | `reason=` |
| `reviewer=` (optional) | `decider=` (required): `{"kind", "id", "agent"?, "credential"?, "freshness"?, "commit"?}` |
| `ai_bom=` | `contributions=`: the steps that led to the decision; `single_model(ai_bom)` (from `tzun_sdk.contributions`) is the list of one model |
| — | `links=`: relations to other records (`derivedFrom`, `reviews`, `supersedes`, `root`, ...) |
| — | `mandate={"mandateId": ...}`: a decision an agent takes under a mandate |

```python
from tzun_sdk.contributions import single_model

await tzun.capture(
    ai_output={"score": 0.87},
    action="approve",
    reason="risk threshold met",
    decider={"kind": "human", "id": "acct:u-4821"},
    contributions=single_model(ai_bom),
)
```

A decider `id` is an opaque identifier (`acct:`, `spiffe:`, `jkt:`, `desc:`),
never a name or an email address; `"commit": True` writes a `cmt:` commitment
instead and keeps its opening in the store (`tzun.deciders.opening`).
Refusals are typed (`InvalidPayloadError`, `InvalidDeciderError`,
`InvalidContributionsError`, `InvalidLinksError`, `InvalidMandateError`,
`MandateRefusedError`, `InvalidAgentDescriptorError`), each with `code`,
`field` and a message, and take no sequence number.

`captured_at` is held to the hosted service's rule for a client-chosen time (an
ISO-8601 date-time no more than five minutes ahead), and a capture under a
mandate takes no `captured_at` or `evidence_id`: the SDK's clock decides
whether it falls in the mandate's window. A prepared capture
(`prepare_assertion_challenge()` then `capture(..., prepared=...)`) passes
the same input to both calls: the members are resolved again and must equal
the prepared ones (`invalid_prepared`).

**attach() and the CLI.** `DecisionInput` takes `action`, `reason`,
`decider` (and `actor`, `links`, `aiSystemId`, `aiBom`); `humanAction`,
`humanReason` and `reviewer` are refused. `tzun capture` takes `--action`,
`--reason`, `--decider` and `--ai-bom-file`.

**New namespaces.** `tzun.agents` (the `tzun-agent/1` catalog),
`tzun.links` (`relate`, `of`, `to`), `tzun.deciders` (`opening`),
`tzun.decision_graph` (`walk`) and `tzun.mandates` (`prepare`, `issue`,
`prepare_revocation`, `revoke`, `confirm`, `get`, `totals`, `events`,
`expire_due`). The mandate ceremonies are verified by the `assertion_verifier`
passed to `Tzun.init()`: the relying party's credential store, behind
`AssertionVerifier` (`WebAuthnAssertionVerifier` is one, over py_webauthn).
A revocation names its mandate:
`revoke(mandate_id=..., prepared=prepare_revocation(...), assertion=...)`.
`decision_graph.walk()` returns `{root, rootEvidenceId, nodes, details,
edges, truncated, truncatedBy}`, the shape of the TS walk (`nodes` are
digests, `details` the nodes). `TzunSync` has the same namespaces, called
synchronously.

**Verify.** `VerificationResult` adds `decider`, `contributions`, `links`,
`mandate`, `agents`, `fieldSet` and `unhashedPayloadMembers`. Readers hash
the stored JSON as written, never a re-serialised model, so a member a writer
added outside the hashed set is reported (`unhashedPayloadMembers`) rather
than dropped.

**Stores.** `Tzun.init()` refuses a store holding records captured under
the 0.7 or an earlier field set with `StoreSchemaOutdatedError`
(`generation` is `"0.7"` or `"before-0.7"`): create a new store. Local
stores gain `decider_openings`, `decider_commitment_secret`,
`tzun_py_agent_descriptors`, `tzun_py_evidence_links`, `tzun_py_mandates`,
`tzun_py_mandate_totals` and `tzun_py_mandate_events`, created by
`ensure_tables()`. The cloud store (`HttpBackendAdapter`) keeps no link
index or mandates: `links.to`, `decision_graph.walk` and the
mandate API refuse on it (`links_not_supported_by_store`,
`mandate_not_supported_by_store`). Its model and agent catalogs are the
hosted service's (`POST /v1/models`, `GET /v1/models/{digest}`, `POST /v1/agents`,
`GET /v1/agents/{digest}`, `GET /v1/agents`); against a backend that does
not serve them, `register_descriptor` raises `ModelCatalogUnsupportedError`
(a wrapped call is then captured with `contributions=None` and
`event=capture_model_not_recordable` is logged), and the agent methods answer
`agent_not_supported_by_store`. Capture does not read the agent catalog over
`HttpBackendAdapter`: the hosted service checks agent references itself. Any other
failed registration in a wrapped call is logged as
`event=connector_hook_failure` and the decision is captured with
`contributions=None`.

`HttpBackendAdapter`'s evidence reads use the routes the hosted service serves
to an API key: `retrieve()` reads `GET /v1/app/evidence/{id}` and
`list()` reads `GET /v1/app/evidence?include=envelope` (newest first, at most
200 a page; `limit` and `offset` are the only filters, and any other is
refused). The adapter keeps each chain's head as the service reports it (the
capture receipt, or a `409 chain_conflict` body) and reads the newest page
once before it has one; that page spans every chain of the key's scope, so on
an account with several chains the service's refusal corrects the first
capture. A capture the service re-stamped onto its own head is stored under
the receipt's sequence and digest, and `capture receipt_restamped` is logged.

## TypeScript and Python

The TypeScript SDK (`@tzun/sdk`, with `@tzun/engine`) and the Python SDK
(`tzun-sdk`) are both built from this repository; this repository's `python/`
holds the Python package. Both implement schema v1.0 and are pinned
to it by `vectors/v1.0-canonical-vectors.json`, so TS-captured envelopes
verify in Python without transformation, and Python-captured envelopes verify
in TypeScript. The packages carry the same version number, but it is the wire
format, not the version number, that makes them compatible (see "Versioning"
below).

## Wire format

Identical between TS and Python. The canonical-serialization rules
(UTF-16-BE key sort, no whitespace, integer-vs-float discipline, lone
surrogate rejection) are enforced byte-for-byte. Vector corpus at
`vectors/v1.0-canonical-vectors.json` is the cross-language ground truth.

The v1.0 hashed field set includes `signoffExpectation`
([Record §9.1](https://spec.tzun.ai/record/1.0/#s9-1)): what signature a
record expects, `None` by default. Both SDKs write it
on every capture, report it from `verify()` (`signoffExpectationValid`,
`signoffExpectationReason`) and from the export's verdict
(`signoffExpectation`), reading it only when the record's digest recomputes
(`None`, `digest_invalid` otherwise), and are held to
`vectors/signoff-expectation-vectors.json`. A store whose records predate it
is refused at `Tzun.init()` with `StoreSchemaOutdatedError`: create a new
store.

## Storage backends

**The two SDKs do NOT share a schema.** The advisory lock they share (below)
serialises two *different* `CREATE TABLE` scripts.

What each side creates:

| | TypeScript | Python |
|---|---|---|
| evidence | `envelopes` | `evidence_envelopes` |
| chain identity / head | `chains`, `chain_state` | (no tables — chain state is derived) |
| recovery ledger | `chain_annotations`, `chain_relinks`, `chain_forks`, `custody_entries` (hashed custody ledger) | `recovery_records` (no custody writer in Python) |
| attestation | inside `envelopes.envelope` | `attestations` |
| incidents | `tamper_incidents` | `tzun_py_tamper_incidents` |
| AI-BOM catalog | `model_descriptors`, `model_descriptor_annotations`, `model_descriptor_aliases` | same names, TS-compatible columns |
| revision log | `envelope_revisions` | same name, **identical** columns — deliberately shared |

The AI-BOM catalog tables and `envelope_revisions` are the genuinely shared
ones. The evidence tables are
disjoint, so **a Python `verify()` / `verify_range()` never sees TS-captured
evidence and a TS verifier never sees Python-captured evidence**, and the two
chain heads advance independently.

`envelope_revisions` is shared on purpose, and it is the
opposite case to `tamper_incidents` below. The columns are identical on both
sides, so `CREATE TABLE IF NOT EXISTS` converges instead of silently no-opping
into a broken adapter — and sharing is what we want, because the log's whole
job is to remember what a record hashed to at capture, and two disjoint logs in
one database would each be blind to half the evidence. The evidence tables stay
disjoint and evidence ids are UUIDs, so the two record populations coexist in
the rows without meeting. The Python SDK writes only revision 0: it has no
recovery path that could write any other (`python/src/tzun_sdk/recovery/manager.py`'s
`relink()` stores a `RelinkRecord` and never rewrites a chain link), so there
is nothing on the Python side that could launder a reseat.

The incident tables do not share a name. The Python table,
`tzun_py_tamper_incidents`, holds a Python-SDK-local incident shape with
entirely different columns from the TS `tamper_incidents`; under one name, in a
shared database, whichever SDK ran `ensure_tables` second would get a
`CREATE TABLE IF NOT EXISTS` no-op against the other's table and then fail on
every `store_incident()`. With the Python table namespaced, the two coexist.

Append-only enforcement also differs: the TS Postgres adapter installs
immutability / delete / truncate triggers, and on the four tables it reads
in id order (`credential_events`, `custody_entries`, `logs`,
`anchor_publications`) refuses a row written at an id its sequence did not hand
out or below one the insert can see, and gives every row an id drawn as it is
written; the Python adapters install
none on their EVIDENCE tables, and those rows can be UPDATEd or DELETEd by any
DB principal. The Python adapter creates none of those four tables
(`python/tests/storage/test_postgres_backdated_id_scope.py` holds it to that).

The one exception is `envelope_revisions`, where both SDKs install the same
UPDATE / DELETE / TRUNCATE refusal (Postgres triggers; SQLite triggers). On
SQLite both also refuse an insert over an existing row, which is how
`INSERT OR REPLACE` would otherwise reseat a revision, and a row at a negative
rowid, which would collide with every later insert. There they
are not optional: the log remembers what a record
hashed to at capture, and a log an insider can DELETE from restores exactly
the silence the revision log exists to remove. On Postgres both create the one function
behind those triggers, `envelope_revisions_block_mutation`, alike: with its
`search_path` pinned to `pg_catalog, pg_temp`, as the TS adapter creates every
function (`tests/cross-sdk/test_postgres_function_parity.py`).
The database-role requirements a Postgres store has are in
`docs/integration/postgres-store.md`.

The Postgres adapters do share the `pg_advisory_lock(2026052501)` key, so
concurrent init from a mixed-language deployment serialises correctly.

## AI-BOM

- The six vendor connectors (openai, anthropic, bedrock, vertex,
  azure_ai, openrouter) extract identical AI-BOM shapes in both SDKs for the
  same `(request, response)` pair. The openrouter descriptor and `aiBom` are
  byte-identical too, down to their digests
  (`tests/cross-sdk/test_openrouter_parity.py`).
- `attach()` detects an OpenAI client pointed at `openrouter.ai` or a
  subdomain such as `eu.openrouter.ai` as `openrouter` in both SDKs (TS by
  `baseURL`, Python by `base_url`). Both record the same endpoint whether or
  not the base URL ends in `/`, and whatever the case of its host's ASCII
  letters or an explicit default port (`:443`, `:80`): openai-python keeps
  the base URL as an `httpx.URL`, which normalises those, and the connector
  applies the same normalisation to the raw string openai-node keeps. httpx
  also IDNA-encodes a non-ASCII host, percent-encodes some path characters
  and reads a port written with leading zeros (`:0443`) as a number; for
  such a base URL the two `attach()` paths may record different endpoints,
  so write it in its encoded, normalised form. Python's `openrouter` vendor
  intercepts the same two methods as its `openai` vendor,
  `chat.completions.create` and `responses.create`; the TS SDK intercepts
  `chat.completions.create` for both.
- `tzun_sdk.hook(...)` (Python) and `tzun.hook(...)` (TS) accept the same
  arguments; Python uses snake_case for kwargs (`ai_output` vs.
  TS `aiOutput`).

## Recommended deployment

For a mixed Python + TS workload, use both SDKs: `tzun-sdk` in the Python
services (its `postgres` extra adds `PostgresAdapter`, `sqlite` adds
`SqliteAdapter`) and `@tzun/sdk`, which brings `@tzun/engine`, in the TS
services.

Both can point at a single Postgres database, and the advisory-lock key
prevents init races — but read "Storage backends" above first: the evidence
tables are disjoint, so the two SDKs will not read each other's records. Point
them at one database only if you want a shared AI-BOM catalog; use separate
databases (or separate schemas) if you expected a shared evidence chain.

## API ergonomics

Per-language differences (snake_case in Python, camelCase in TS) live at
the API surface only. The wire format is invariant.

| TS                                | Python                                   |
|-----------------------------------|------------------------------------------|
| `await tzun.capture({...})`       | `await tzun.capture(action=..., decider=..., ...)` |
| `tzun.hook(vendor, req, resp)`    | `await tzun_sdk.hook(vendor, req, resp, tzun=tzun)` |
| `tzun.attach(client)`             | `tzun.attach(client)` / `tzun_sdk.attach(client, tzun=tzun)` |
| `tzun_capture: { action, reason, decider }` | `tzun_capture=DecisionInput(action=..., reason=..., decider=...)` |

## Versioning

- Compatibility comes from the record's wire format, not from the package
  version. Both SDKs write `envelopeVersion` `e1` and `schemaVersion` `v1.0`
  ([Record §4.3](https://spec.tzun.ai/record/1.0/#s4-3)), and the Python
  `verify()` raises `WireFormatMismatch` on any other `schemaVersion`.
- Within `v1.0` the hashed field set was revised in place by 0.7.0 and again
  by 0.8.0. `Tzun.init()` refuses a store written under an earlier field set
  with `StoreSchemaOutdatedError` (see "Stores" above), and `verify()` names the
  earlier set a mismatched digest recomputes under in `fieldSet`
  ([Record §4.1](https://spec.tzun.ai/record/1.0/#s4-1)).
- `tzun-sdk` and the TypeScript packages `@tzun/sdk` and `@tzun/engine` carry
  the same version number and are released together from one tag. Before 1.0,
  a minor release may change the API or the record's field set; the sections
  above say what changed.
