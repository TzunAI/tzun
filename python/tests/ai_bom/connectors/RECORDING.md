# Connector Fixture Recording Guide

## Purpose

Fixtures in `fixtures/<vendor>/` are static JSON recordings of real vendor SDK
request/response pairs. They exercise every field consumed by each connector's
`build_ai_bom(params, response)` implementation without requiring live API calls.

## Directory structure

```
fixtures/
  openai/
    happy.json
    optional_fields_populated.json
    optional_fields_absent.json
    azure_hit.json          # openai-only: Azure deployment resolved in known-models
    azure_miss.json         # openai-only: Azure deployment unknown, pass-through
  anthropic/
    happy.json
    optional_fields_populated.json
    optional_fields_absent.json
  azure_ai/
    happy.json
    optional_fields_populated.json
    optional_fields_absent.json
  bedrock/
    happy.json
    optional_fields_populated.json
    optional_fields_absent.json
  vertex/
    happy.json
    optional_fields_populated.json
    optional_fields_absent.json
```

## Fixture JSON schema

```json
{
  "recordedAgainst": "<vendor-sdk-name> <version>",   // REQUIRED: pinned SDK version
  "recordedAt": "YYYY-MM-DD",
  "request": { ... },   // kwargs passed to the vendor SDK call
  "response": { ... }   // response.model_dump() or equivalent dict
}
```

`recordedAgainst` is mandatory — it documents which SDK version produced the
fixture shape so future drift is detectable.

## Recording a new fixture

1. Make a real vendor SDK call against the actual API (or a sandbox).
2. Capture the request kwargs as a plain dict.
3. Call `response.model_dump()` (or equivalent) to get the response dict.
4. Write them to a new `<case>.json` file in the vendor directory.
5. Add `"recordedAgainst"` and `"recordedAt"` metadata.

## Minimum coverage per vendor

- `happy.json` — all commonly-used fields populated; response.model is resolvable.
- `optional_fields_populated.json` — maximum optional-field coverage.
- `optional_fields_absent.json` — minimal request (only required fields); response
  model still present but optional response fields absent.

## Case naming conventions

- Additional cases: descriptive name (e.g. `azure_hit.json`, `azure_miss.json`).
- openai-specific Azure cases exercise the reverse-lookup path.

## Version pinning rule

When a vendor SDK releases a new major version with changed field shapes,
add a new fixture set named `<vendor>_v2/` or update the existing fixtures
with the new `recordedAgainst` tag and verify the connector handles both shapes
via the `optional_fields_absent` baseline.
