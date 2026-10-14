# schema/

The **canonical-serialization schema** of Tzun envelopes is defined by the
TypeScript type declarations in `packages/engine/src/types/*.ts`, augmented
with `@tzun-*` JSDoc annotations. The TS types ARE the IDL — no separate
YAML / JSON Schema / Protobuf file ships in v1. The serialization rules
themselves are stated in the DEO specification,
[Record §3](https://spec.tzun.ai/record/1.0/#s3).

## Supported JSDoc annotations

### `@tzun-canonical-sort <strategy>`

Indicates the sort strategy used when canonicalizing this type. The only
supported strategy in v1 is `utf16` (UTF-16 code-unit ordinal comparison, the
member order of [Record §3.3](https://spec.tzun.ai/record/1.0/#s3-3)).
Listed as an annotation rather than implicit so future strategies
(e.g., NFC normalization) can be added without breaking the format.

```ts
/**
 * @tzun-canonical-sort utf16
 */
export interface EvidencePayload {
  evidenceId: string;
  /* ... */
}
```

### `@tzun-hashed-fields <comma-separated field list>`

Names the canonical hashed-field set used when this type is the input to
a digest computation. The order of the listed fields is informational;
the canonicalizer sorts them at serialization time. The set on
`EvidencePayload` is the eleven names of
[Record §4.1](https://spec.tzun.ai/record/1.0/#s4-1).

```ts
/**
 * @tzun-canonical-sort utf16
 * @tzun-hashed-fields action, aiOutput, aiSystemId, capturedAt, contributions, decider, evidenceId, links, reason, sequenceNumber, signoffExpectation
 */
export interface EvidencePayload {
  /* ... */
}
```

### `@tzun-omit-when-unset`

Marks an optional (`?:`) property that has no wire key when it is unset. A TS
property left undefined has no JSON key, while a Pydantic `x: T | None = None`
field serialises as `"x": null`; the Python model generated for a tagged
property drops the key unless it was set, so an absent key stays absent
across a Python round trip and an explicit `null` survives. The code generator
refuses it on a required property.

## Consumers

| File | Status | Purpose |
|------|--------|---------|
| `migrations/sqlite/0001_init.sql` | Reference | The **Python** SQLite adapter's DDL, kept here for readers. It is not read at runtime (the adapter carries its own inline copy) and it is NOT the TypeScript adapter's schema — the two SDKs create different tables. See `python/MIGRATION.md`. |
| `README.md` | Active | This file. |

Each Postgres adapter carries its own inline DDL; there is no Postgres file
here.

- TypeScript SDK (`packages/engine/src/canonical.ts`,
  `packages/engine/src/envelope.ts`) — runtime types from
  `packages/engine/src/types/`.
- `scripts/codegen-python.ts` — parses the annotated TS sources via the
  TypeScript compiler API and emits
  `python/src/tzun_sdk/_generated/models.py`. `canonical.py` and `chain.py`
  beside it are hand-maintained ports that the script only checks are
  present; the `cross-sdk` CI job holds them to the TypeScript engine. Drift
  in the generated file is enforced by CI's `codegen-drift` job via
  `git diff --exit-code`.

## Cross-references

- Test vectors: [`vectors/v1.0-canonical-vectors.json`](../vectors/v1.0-canonical-vectors.json) — the committed conformance corpus.
- Canonical serialization: [Record §3](https://spec.tzun.ai/record/1.0/#s3); the hashed field set: [Record §4.1](https://spec.tzun.ai/record/1.0/#s4-1).
