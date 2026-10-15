# Changelog

All notable changes to `@tzun/sdk`, `@tzun/engine` and the Python package
`tzun-sdk` are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with one project-specific rule:

> **Anything that changes a computed digest is breaking.** The hashed field set,
> the canonicalization rules and number/string formatting are a contract with
> every record already captured. Record format v1.0 is not yet frozen
> ([Specs §2](https://spec.tzun.ai/#s2)); while it is not, a change to the hashed
> field set can be made under the same `v1.0` tag as a breaking release whose
> notes here say how to rebuild a store. A change to the canonicalization rules
> or number/string formatting gets a new schema version and a migration note
> here, not a patch release, as does any change to the set once v1.0 is frozen.

`@tzun/sdk`, `@tzun/engine` and `tzun-sdk` are versioned **in lockstep**. The
SDK depends on the engine through the pnpm `workspace:` protocol, which is
rewritten to the engine's exact version at publish time.

## [Unreleased]

### Added

- An `openrouter` connector for models served through the OpenRouter gateway
  (TzunAI/tzun#14). A model called through OpenRouter had no truthful AI-BOM:
  an OpenAI SDK client pointed at OpenRouter was recorded as `openai`, and the
  `nvidia-nim` connector run on an OpenRouter-served model recorded a NIM call
  with no endpoint, so the gateway disappeared from the record. The connector
  records the descriptor `vendor` as `openrouter`, the served id
  (`response.model`, variant suffix such as `:free` included) as `modelName`
  with `modelVersion: 'unknown'`, its author prefix (`nvidia`, `meta-llama`,
  `x-ai`, ...) as `trainedBy`, the upstream OpenRouter reports
  (`response.provider`, e.g. `Nvidia`) as `infrastructure.provider`, and the
  gateway base URL the client called as `infrastructure.endpoint`, without
  credentials, query or trailing `/`, its host lowercased and a default port
  dropped. The tier is `vendor-asserted`, asserted by the gateway. It assumes
  nothing it was not told: no `model` in the response gives no AI-BOM, and a
  missing provider or base URL is `null`. A value the AI-BOM rules would
  refuse is recorded as `null` rather than failing the capture: `maxTokens`
  and `seed` are kept only as safe integers, an infrastructure string only up
  to 256 UTF-16 code units, and `stopSequences` only when there are at most 16
  of at most 256 code units each (never truncated). The TypeScript and Python
  connectors record the same bytes for the same call.
- TypeScript: `tzun.attach()` detects an OpenAI-compatible client whose base
  URL host is `openrouter.ai` as `openrouter` and records its base URL;
  `wrapOpenRouter` pins the vendor for any base URL. `tzun.hook('openrouter',
  request, response)` records the endpoint passed as
  `request.openrouter_endpoint`. `SUPPORTED_VENDORS` has eight labels. The
  importer exports the `openRouterAuthor` and `openRouterVariantBase` id
  helpers.
- Python: the `openrouter` connector (`tzun_sdk.ai_bom.connectors.openrouter`,
  registry key `openrouter`), so `hook("openrouter", request, response)`
  works, with the endpoint passed as `request["openrouter_endpoint"]`.
  `attach()` detects an OpenAI client whose `base_url` host is
  `openrouter.ai` as `openrouter` and records its base URL; `vendor=
  "openrouter"` pins the vendor for any base URL. `parse_model_id` gains the
  `openrouter` rule, and `openrouter_author` and `openrouter_variant_base` are
  the id helpers.
- 39 `openrouter` entries in the bundled known-models reference
  (`data/known-models.json`, version `2026-10-15`), for selected current
  models of OpenAI, Anthropic, Google, Meta, Mistral AI, xAI, DeepSeek, Qwen,
  NVIDIA, Microsoft, Amazon, Cohere, Moonshot AI, Z.ai and MiniMax on
  OpenRouter: model type, license, OpenRouter model page and, for published
  weights, the Hugging Face repository. A model without an entry is still
  recorded, with `license`, `modelType` and `modelCardUrl` null. A `:free` or
  `:batch` variant enriches from its base model's entry and keeps its own
  `modelName`, in both SDKs. Three license labels join the
  `<maker>-commercial` vocabulary for models whose weights are not published:
  `meta-commercial`, `xai-commercial` and `amazon-commercial`. Published
  weights take the license id on the Hugging Face card, or, where the card
  names none, a slug of the repository's license title:
  `mistral-modified-mit` for Mistral Medium 3.5. The rules are in
  `docs/integration/ai-bom-runbook.md`.
- `'openrouter-known-models'` in `ModelDescriptorSource` (`@tzun/engine`).

### Changed

- A capture through an attached OpenAI SDK client whose base URL host is
  `openrouter.ai` now registers a descriptor with `vendor: 'openrouter'`, the
  served id as `modelName`, and an `infrastructure` block, where it registered
  `vendor: 'openai'` with no infrastructure. This holds in both SDKs. Records
  already captured are unchanged and still verify. `tzun.attach(client, {
  vendor: 'openai' })` (TypeScript) and `attach(client, tzun=tzun,
  vendor="openai")` (Python) keep the old classification.

### Removed

- `uuid` is no longer a dependency of `@tzun/sdk`. Nothing imports it
  (TzunAI/tzun#2).
- `rich` is no longer a dependency of `tzun-sdk`. Nothing in the package
  imports it; the `tzun` command is built on `typer`, which depends on `rich`
  itself (TzunAI/tzun#2).
- The `sigstore` extra of `tzun-sdk`, which `all` included. It installed
  `sigstore`, which nothing imports: `SigstoreBackend` is not implemented and
  raises `NotImplementedError`, as before. `sigstore` 4.5 caps `rich` below 16
  and `rfc3161-client` below 1.1, so raising either floor would have made
  `[sigstore]` and `[all]` impossible to install (TzunAI/tzun#2).

### Fixed

- `@tzun/sdk` lists `@types/better-sqlite3` and `@types/pg` as dependencies,
  not dev dependencies. Its declarations import types from `better-sqlite3`
  and `pg`: the storage extension and log-store signatures take a
  `better-sqlite3` database and a `pg` pool. A project that type-checks
  library declarations (`skipLibCheck: false`) and did not install the two
  `@types` packages itself failed to compile against the packed SDK with
  TS7016. The ranges, `^7.6.0 || ^9.6.0` and `^8.11.0`, also accept the
  older versions a project may have installed itself. CI now packs
  `@tzun/engine` and `@tzun/sdk` and compiles two strict consumers of the two
  tarballs, one with nothing else installed and one with the oldest version
  of each `@types` package the ranges accept
  (`scripts/check-packed-types.sh`) (TzunAI/tzun#9).

## [0.8.2] — 2026-10-06

**The first public release of the source.** Tzun records a tamper-evident
Decision Evidence Object (DEO) when a human acts on an AI recommendation:
canonical serialization, a SHA-256 digest, an append-only hash chain per
evidence chain, optional WebAuthn sign-off, RFC 3161 timestamps, Merkle
anchoring, and a record of the AI systems that contributed to the decision. The
record format, its verification rules, the proof bundle, the anchor format and
the conformance vectors are specified at [spec.tzun.ai](https://spec.tzun.ai).

### Licence and packages

- The source is published so that it can be read. No licence is granted: see
  [`LICENSE.md`](./LICENSE.md).
- `@tzun/sdk` and `@tzun/engine` (npm) and `tzun-sdk` (PyPI) are not published.
  Each manifest marks its package unpublishable, and the release workflows stop
  while one does.
- The conformance vectors in `vectors/` are CC0-1.0.
- The code of conduct in `CODE_OF_CONDUCT.md` is the Contributor Covenant 2.1,
  under CC BY 4.0.

### Changed

- `TzunWebAuthn.verifyAssertion()` refuses an assertion whose `clientDataJSON`
  states `crossOrigin: true` and names a `topOrigin`, unless that `topOrigin`
  is listed in the new `WebAuthnConfig.allowedTopOrigins`, which it passes to
  `@simplewebauthn/server` as `expectedTopOrigin`. 14.x refuses such a
  response when the caller names no expected top origin; 13.3.3 did not check
  the top origin. A ceremony in the browser-extension side panel runs in a
  cross-origin frame, so a relying party that verifies one lists the
  extension's origins:
  `new TzunWebAuthn({ ..., allowedTopOrigins: ['chrome-extension://<id>'] })`.
  The option takes the same list as `allowedTopOrigins` for `Tzun.verify()`
  and `verifyAttestation()`, but `verifyAssertion()` checks it only for an
  assertion that states `crossOrigin: true` and names a `topOrigin`;
  `assertionProvenance.topOriginValid` checks every assertion. An assertion
  that names no `topOrigin` (a ceremony run directly in a tab, a cross-origin
  frame in Safari, or one that does not state `crossOrigin`) verifies as
  before whether or not the option is set. 14.x also refuses an assertion that
  names a `topOrigin` without stating `crossOrigin: true`.

### Removed

- `mandateEventLeaf` (`@tzun/engine`) and `mandate_event_leaf`
  (`tzun_sdk.mandate`), and the `leaf` member of the event bodies in
  `vectors/mandate-vectors.json` and `vectors/v1.0-worked-example-vectors.json`.
  Nothing used them: no mandate log is built, stored or anchored, and the form
  of a mandate log's leaves is settled when one is. `mandateEventBodyDigest` and
  `mandate_event_body_digest` (`SHA-256(C(body))`) are unchanged.

### Security

- `@simplewebauthn/server` is upgraded from 13.3.3 to 14.0.3. In 13.3.3,
  registration verification fetched the CRL URL named by each certificate in
  an attestation statement's `x5c`, and cached the result process-wide, before
  checking that the certificate chained to a trust anchor. It did so whenever
  the format had a trust anchor to chain to: `apple` and `android-safetynet`
  have default roots, and `android-key` uses the `x5c`'s own last certificate.
  So a crafted registration response made the server request a URL the client
  chose. Since 14.0.2 the library checks revocation only along a chain that has
  reached a supplied trust anchor, verifies a CRL's signature against the
  issuer's key, and keys its CRL cache by the issuer's key identifier. The
  advisories
  ([GHSA-j3h4-m3m2-7p7j](https://github.com/MasterKale/SimpleWebAuthn/security/advisories/GHSA-j3h4-m3m2-7p7j),
  [GHSA-2g3p-m8c9-hhwh](https://github.com/MasterKale/SimpleWebAuthn/security/advisories/GHSA-2g3p-m8c9-hhwh))
  list 14.0.1 as the affected version; 13.3.3 has the same code path.
- 14.0.3 still fetches for `android-key`. That format's verifier validates the
  `x5c` against the `x5c`'s own last certificate, and checks that this root is
  a known Google root only afterwards, so a response whose leaf certificate is
  issued by a root the client made still has the server fetch the CRL URLs the
  certificates of that chain name. `TzunWebAuthn.finishRegistration()`
  therefore replaces the attestation statement of every registration response
  with format `none` and an empty statement before verifying it: the library
  reads no attestation certificate, and registration verification fetches
  nothing, whatever the response. The SDK stores nothing from an attestation
  statement, and a response is accepted exactly when the same authenticator
  data sent with format `none` would be. `startRegistration()` asks for
  attestation `none`, as it did by default; it now says so explicitly.
- `TzunWebAuthn.finishRegistration()` accepts only the algorithms
  `startRegistration()` offers: Ed25519 (-8) and ES256 (-7). It used to verify
  against the library's default list, which includes RS256, and stored a
  credential of an algorithm other than those two labelled ES256. It takes the
  label from the credential key alone, and refuses a key that states no
  algorithm it can read, where it used to fall back to the response's
  `publicKeyAlgorithm` field and then to ES256.

### Before 0.8.2

Earlier versions were not publicly released. Their history is not part of this
repository. The format versions they implement are listed at
[spec.tzun.ai](https://spec.tzun.ai).
