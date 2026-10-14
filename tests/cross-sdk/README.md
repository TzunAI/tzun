# tests/cross-sdk/

Cross-SDK wire-format parity tests: the same corpus and the same operations run
through both SDKs, asserting byte-identical results.

This directory validates that the schema is implemented byte-for-byte
identically across:

- The TypeScript SDK (sourced from `src/` and `packages/engine/`, packaged as
  `@tzun/sdk` and `@tzun/engine`).
- The Python SDK (`tzun_sdk`, sourced from `python/src/tzun_sdk/`).

## What is here

They are pytest modules — Python drives, and shells out to the TypeScript
harness for the TS half of each comparison.

| Test | Purpose |
|------|---------|
| `test_canonical_parity.py` | Replays every entry in `vectors/v1.0-canonical-vectors.json` through both SDKs and asserts byte-equal canonical output. |
| `test_ts_to_py_roundtrip.py` | Capture in TS → verify in Python. |
| `test_capture_contract.py` | TS `HttpTransport.capture()` and Python `HttpBackendAdapter.store()` build identical `POST /v1/evidence` request bodies. |
| `test_connector_parity.py` | The five shared vendor connectors extract identical AI-BOM shapes from the same `(request, response)` pair. |
| `test_integrity_parity.py` | Digest / chain / integrity-block agreement across the two implementations. |
| `test_custody_hash_parity.py` | The custody entry hash and the custody-trail verdict: both SDKs held to `vectors/custody-entry-hash-vectors.json`, then the same verdict on a TS-minted trail, clean and rewritten. |
| `test_custody_entry_parity.py` | The custody entries a Python client sends carry no key a TS client would leave out (`@tzun-omit-when-unset`), and both SDKs read a record with mirrored entries and agree on its digest. |
| `test_assertion_provenance_parity.py` | What a WebAuthn assertion states (`origin`, `crossOrigin`, `topOrigin`, the UP/UV/BE/BS flags) and the binding check, read the same way by both SDKs. |
| `test_webauthn_challenge_parity.py` | The decision-binding challenge, `base64url(SHA-256("tzun-decision-v1" ‖ canonicalDigest))`, derived identically by both SDKs. |
| `test_model_id_parity.py` | Both model-id parsers split every bundled known-models wire id, and the edge shapes where JS and Python regex semantics differ, the same way. |
| `test_merkle_vectors.py` | Python only, no Node: `vectors/merkle-rfc6962-vectors.json` and `vectors/merkle-consistency-vectors.json` through `tzun_sdk.attestation.merkle`, byte for byte. |
| `test_merkle_parity.py` | The TS engine and the Python port agree on every root and inclusion and consistency proof for trees of 1 to 64 leaves, and on every verifier answer over the vectors and hostile inputs (`ts-harness/merkle.ts`). |
| `test_evidence_log_origin_parity.py` | Evidence-log origins (Anchor §4.3.2) agree across Python, TypeScript and SQLite SQL, held to `vectors/evidence-log-origin-vectors.json`, and a TypeScript-created store's trigger writes a record's leaf for a Python writer (Tree §5.2). |
| `test_sqlite_revision_guard_parity.py` | Both SDKs guard the shared SQLite `envelope_revisions` table with the same triggers, and the TypeScript store's guards refuse a REPLACE and a negative rowid from a Python connection. |
| `test_postgres_function_parity.py` | Both SDKs create their Postgres functions with the search_path pinned, and the one function they share says the same thing in both (no database: it compares the statements, `ts-harness/log-store.ts`). |
| `test_checkpoint_vectors.py` | Python only: `vectors/checkpoint-vectors.json` through `tzun_sdk.attestation.checkpoint` and `verify_anchor` (steps 1 to 5). |
| `test_anchor_e2e_vectors.py` | Python only: `vectors/anchor-e2e-vectors.json`, and `verify_anchor`'s verdict on every record (the `anchor` extra). |
| `test_evm_anchor_vectors.py` | Python only: `vectors/evm-anchor-vectors.json`, the publisher-manifest validity bounds of tzun-anchor/1 §9, and `verify_evm_publication`'s verdict on every case in each of its three modes (the `anchor` extra). |
| `test_anchor_artifact_roundtrip.py` | An anchored envelope (`nonRepudiation.anchor`, Anchor §8) crosses TS → Python → TS unchanged and still verifies in TS; an anchor this build does not read crosses unchanged, and TS abstains on it. |
| `test_anchor_fill_parse.py` | Records the TS anchor scheduler filled (Anchor §8.4, §11) parse in the Python models unchanged, and the artifact still verifies in TS after the round trip. |
| `test_anchoring_chain_audit.py` | The Python verifier knows the EVM networks the TypeScript SDK's `DEFAULT_EVM_NETWORKS` lists, and reads a Glamsterdam block header as the TypeScript anchor writer rebuilds it. |
| `test_anchor_verify_parity.py` | The anchor verifier in both SDKs (`ts-harness/anchor-verify.ts`): checkpoints, origins, RLP, transactions, headers, trie proofs, `verifyEvmPublication` and `verifyAnchor`, down to every check and fact (the `anchor` extra). |
| `test_rfc3161_conformance_parity.py` | The RFC 3161 client's check at capture (tzun-anchor/1 §10.5 steps 1 to 3, `ts-harness/rfc3161-conformance.ts`): the same answer on every stored authority token, a token breaking each rule, the mock authority's token, every byte of three tokens flipped, and certificates and keys Node reads by OpenSSL's rules; the same tokens kept and the same `attestation_timestamp_nonconformant` event end to end, on BER and on every byte the clients' readers decide on, flipped. The Python verifier's limits (an EC curve `cryptography` does not implement) are pinned where the answers differ. |
| `test_anchor_anvil_store.py` | A store anchored on anvil by the TypeScript SDK (`ts-harness/anvil-store.ts`), every record verified by both SDKs reading the node. Runs where the anvil suite runs (Docker; under CI only with `TZUN_ANVIL=1`): locally, and in `.github/workflows/anvil.yml` after the anvil suite. ci.yml's `cross-sdk` job skips it. |
| `ts-harness/*.ts` | The TypeScript side the pytest modules invoke: `index.ts`, and `anchor-verify.ts`, `anvil-store.ts`, `log-store.ts`, `merkle.ts` and `rfc3161-conformance.ts` for the modules that name them. |
| `test_v1_0_worked_example_vectors.py` | Python recomputation of `vectors/v1.0-worked-example-vectors.json`: W1 to W7 and their sub-vectors. |
| `test_decider_vectors.py`, `test_contributions_vectors.py`, `test_links_vectors.py`, `test_mandate_vectors.py`, `test_agent_descriptor_vectors.py`, `test_store_generation_vectors.py`, `test_cross_sdk_parity_vectors.py`, `test_signoff_expectation_vector_digests.py` | The record's v1.0 vector files (`decider`, `contributions`, `links`, `mandate`, `agent-descriptor`, `store-generation`, `cross-sdk-parity`, `signoff-expectation`): Python recomputes every value a file pins as bytes or a digest, and holds the generated strict models to the rules they can enforce. Each also replays the file's rule answers through the Python SDK's rule module for that member (`tzun_sdk.decider`, `.contributions`, `.links`, `.mandate`, `.agents`, `.record_rules`), through the `sdk_rule` fixture of `conftest.py`, which skips, naming the module or function, while it is not in the SDK. |
| `ts/*.test.ts` | The TypeScript replays of the same files, run by `pnpm test` (jest): the engine gives every answer each file states, and `vector-files-current.test.ts` fails when a file is not what its generator prints. |

## The vector files and their generators

The record's vector files under `vectors/` (the `v1.0-worked-example`,
`v1.0-canonical` and `v1.0-integrity` files, and the eight above) each have a
generator in `scripts/` (`generate-*-vectors.ts`), which states each expected
answer and stops, printing the case, when the engine disagrees.
`pnpm run regenerate:vectors` writes them all, in order; `-- --check` reports
any that differ; `-- --only <words>` limits the run. The anchor-e2e vectors and
the b1 corpus come from an anvil run (`-- --anvil`, Docker), regenerated once
per release.

## How CI runs it

The anchor tests need the Python SDK's `anchor` extra (`pip install -e 'python[anchor]'`).
Without it they skip, except under CI, where they fail: a parity test that
skips in CI is one that never runs.

The `cross-sdk` job in `.github/workflows/ci.yml` runs
`python -m pytest tests/cross-sdk/ -v`, after building `@tzun/engine` and
installing the Python SDK from `python/`. It needs BOTH toolchains — a
Node-only or Python-only environment cannot run this directory.
