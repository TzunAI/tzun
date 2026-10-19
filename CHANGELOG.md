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

## [0.9.1] — 2026-10-18

### Changed

- The Python package description, the Python README, the Python module
  docstring, the `tzun --help` text and the demo banner now describe Tzun as
  "tamper-evident records for AI decisions" (title case in the demo banner).
  No API, record or stored value changes.

## [0.9.0] — 2026-10-17

The verifiers follow the specification as revised on 17 October 2026
([spec.tzun.ai](https://spec.tzun.ai)): an `rfc3161/1` publication by
tzun-anchor/1 §10.5 steps 1 to 4 with only the reasons of §10.1, the
`custody.ledger` row of Verification §4.3, the null slots of Bundle §3.1, and
item 13 of tzun-anchor/1 §10.4. The RFC 3161 token checks also follow
tzun-anchor/1 §10.5 steps 1 and 3 as revised, which settle the token rules step
1 left open and which requirement of step 3 decides first. The minor version
moves because reason strings and verdicts change: a caller that matches on them
should read the list below. No digest, record or stored value changes.

### Changed

- **`rfc3161/1` publications** (`verifyAnchor` and `verify_anchor`, and so
  `verifyBundle()` and the anchor of `verifyAttestation`). Both checks follow
  tzun-anchor/1 §10.5 in order, whether or not RFC 3161 roots are supplied:
  `anchor.tsa.token[i]` is steps 1 to 3 (the token is the base64 of a DER
  `TimeStampResp`, its imprint is SHA-256 over P, its signature, signer
  binding and timestamping-only extendedKeyUsage hold), which need no root,
  and `anchor.tsa.trust[i]` is step 4, the path to a supplied root. The
  earliest step that fails settles the outcome, and the other check is then
  `blocked_by` it. The TypeScript SDK now checks the token on the record
  token's path (`verifyRfc3161Steps`), and the Python SDK on its twin
  (`_rfc3161_steps`). What changes (TypeScript and Python unless one is
  named):
  - The reasons `rfc3161_imprint_mismatch` and `rfc3161_signature_invalid`
    are gone from `AttestationAnchorReason`; §10.1 lists neither. A token over
    another value, or over P's bytes under another hash, is `false`,
    **`imprint_mismatch`**. A token whose signature, signer binding or
    timestamping-only extendedKeyUsage fails is `false`,
    **`verification_failed`**. A caller that matched the old strings must
    match the new ones.
  - With no root supplied, a token that holds steps 1 to 3 has
    `anchor.tsa.token[i]` `checked-correct`; it was `not-checked`,
    `blocked_by:anchor.tsa.trust[i]`. The trust check is still `not-checked`,
    `no_matching_trust_anchor`, and the publication `null`,
    `publication_not_checked`.
  - With no root supplied, a token over another value is `false`,
    `imprint_mismatch`, one whose signature or signer fails is `false`,
    `verification_failed`, and one that is not DER (a BER encoding of the same
    values, say) is `false`, `malformed_publication`. Each was `null`,
    `publication_not_checked`. The anchor is then `false`, with no fact
    from it (§10.6), where it stood on its other publications before.
  - With roots supplied (TypeScript), a token that fails step 2 or 3 now has
    `anchor.tsa.trust[i]` `not-checked`, `blocked_by:anchor.tsa.token[i]`; the
    trust check was reported beside it, often `checked-correct`. A token over
    another value is `false` whether or not its path is valid; it was
    `null`, `no_matching_trust_anchor`, when its path did not validate.
  - With roots supplied (TypeScript), a path that reaches a supplied root
    and holds on none (a certificate outside its validity at `genTime`, a
    certificate the root's key did not sign) is `false`,
    `verification_failed`, on `anchor.tsa.trust[i]`, and so the anchor is
    `false`. It was `null`, `no_matching_trust_anchor`.
  - With roots supplied (Python), `anchor.tsa.token[i]` is decided by steps 1
    to 3 as above; it was `not-checked`, `missing_dependency`, for every
    readable token (an unreadable one was already `false`,
    `malformed_publication`). Once they hold, `anchor.tsa.trust[i]` is `not-checked`,
    `missing_dependency` (§10.5 step 5): this SDK has no certificate-path
    verifier, so it never reports an RFC 3161 publication `true`.
  - An unforeseen failure of the token steps is `anchor_verifier_error`, the
    verifier's failure (§10.1); it was `missing_dependency`.
  - A publication's `rfc3161` member (`{ genTime, tsaSubject }`) is read from
    the token once step 1 holds, whatever the outcome, in both SDKs. Only a
    `true` publication's `genTime` counts toward `existedBy`, as before.
- **RFC 3161 tokens: tzun-anchor/1 §10.5 steps 1 and 3 as revised.** Both
  SDKs' token checks (`readRfc3161Token` and `checkSignatureAndSigner`, and
  their Python twins in `_rfc3161_steps`) hold every token to them: the
  record's own token (`ts.record.token`), an `rfc3161/1` publication's
  (`anchor.tsa.token[i]`), `verifyTimestampToken`, the timestamp of
  `verifyAttestation`, and the capture check (`timestampConformance`,
  `timestamp_conformance`). A token that fails step 1 is `malformed_token`,
  `malformed_publication`, `unparseable_token` or, at capture, `malformed`, as
  before. What changes:
  - Step 1 now refuses a token whose `certificates` hold an element that is
    not a certificate, a tagged `CertificateChoices` of RFC 5652 §10.2.2; it
    was skipped.
  - Step 1 now decodes the `TSTInfo` whole (RFC 3161 §2.4.2): after `genTime`,
    only `accuracy`, `ordering`, `nonce`, `tsa` and `extensions`, each
    optional, in that order. `millis` and `micros` are each an INTEGER from 1
    to 999, `tsa` is one GeneralName (its tag and form only), and `extensions`
    holds at least one extension. Nothing after `genTime` was read, so a token
    with anything else there, or one of these out of its shape, is now
    malformed.
  - Step 1 now refuses a fraction of a second in a certificate's validity
    (RFC 5280 §4.1.2.5.2); `genTime` keeps its fraction.
  - Step 1 now reads a year from 0000 to 0099 in a `GeneralizedTime`, in a
    validity and in `genTime`, with leap years by the Gregorian rule in every
    year. The TypeScript reader took such a year as 1900 to 1999 and refused the
    date, and the Python reader refused it to match, so such a token was
    malformed.
  - Step 1 now holds what follows a certificate's `subjectPublicKeyInfo` to a
    primitive `issuerUniqueID` `[1]`, a primitive `subjectUniqueID` `[2]` and a
    constructed `extensions` `[3]` holding one SEQUENCE, each at most once, in
    that order. The reader took the first constructed `[3]` from anywhere
    after the key, and left the rest to OpenSSL's X.509 reader (and the Python
    reader to its model of it), which read a constructed `issuerUniqueID` or
    `subjectUniqueID` (BIT STRING segments, say), so a certificate with one was
    read; it is now malformed. A certificate whose `[3]` is retagged as a
    constructed `[2]` was already refused by that reader, and is now refused by
    this rule at step 1.
  - Step 1 now has the unrestricted CHARACTER STRING (universal 29)
    constructed, and OID-IRI and RELATIVE-OID-IRI (35, 36) primitive, as X.690
    encodes them. 29 was required primitive, and 35 and 36 were read in either
    form.
  - Step 3: a requirement the verifier can check now decides before one that
    needs what it lacks. A token whose signer key is left unread (a key
    algorithm or curve the verifier does not implement), or whose
    `digestAlgorithm`, `signatureAlgorithm` or `ESSCertIDv2` hash algorithm it
    does not implement, is `verification_failed` when its signature (under an
    algorithm the verifier implements), its signer binding or its
    timestamping-only extendedKeyUsage fails. It was `missing_dependency`, and
    stays so when every requirement the verifier can check holds.
  - Unchanged, and now tested at their edges in both SDKs: the decoder bounds
    of step 1 (constructed elements nested at most 64 deep and at most 100,000
    elements, in the `TimeStampResp`, the `TSTInfo` and each typed extension
    value, each on its own), and the signature verified over the signed
    attributes as the token carries them, never a re-encoding.

  Every stored public authority's token, and every token in `vectors/`, reads
  as before.
- **`custody.ledger`** (`verifyBundle()`). This version verifies no custody
  material, and the row is never `checked-correct` (Verification §4.3,
  Bundle §6): the report no longer vouches for custody rows, as the
  specification says it must not.
  - A `custody` slot with rows, or any slot other than `null` or an object
    whose `entries` is an empty array, abstains, **`unsupported_artifact`**.
    It was `checked-correct` when the rows and the envelope's mirror agreed,
    so such a bundle now exits 4 unless the auditor allows unchecked rows; it
    exited 0.
  - The reasons the custody ledger check reported (`row_prev_mismatch`,
    `row_hash_mismatch`, `digest_moved_since_entry`, `unhashed_after_hashed`,
    `mirror_hash_mismatch`, `mirror_prev_mismatch`, `mirror_fields_mismatch`,
    `mirror_entry_missing`, `record_missing`) and
    `not_in_bundle:custody_entries` no longer appear in a report;
    Verification §2.3 lists none of them.
  - A slot that holds no row (`null`, or `entries` empty) beside an envelope
    whose `custodyChain` holds a mirror entry (an object with a 64-hex
    `entryHash`) is `checked-wrong`, `mirror_entry_unexpected`, as before,
    also when another entry fails before it, where the first ledger failure
    (such as `unhashed_after_hashed`) was reported. Without a mirror entry it
    is `not-checked`, `not_applicable`, as before.
  - The store's own checks, the read verdict and the custody trail scan,
    still verify the rows with `verifyCustodyLedger`.

### Fixed

- **tzun-anchor/1 §10.4 item 13.** When no matching manifest entry is valid at
  the block time the header source confirmed, the publication is `false`,
  `evm_sender_mismatch`, on `anchor.evm.tx`, and `anchor.evm.canonical` is now
  `checked-correct` with the facts of item 14 (`chain`, `namespace` `null`,
  `network`, `blockTime`, `inclusion`); it was `not-checked`,
  `blocked_by:anchor.evm.tx`. Only a bundle without a block header reaches
  this: with one, item 6 decides first and the canonical check is blocked, as
  before. `EvmPublicationFacts` (`chain`, `namespace`, `network`,
  `blockTime`) are set whenever the canonical check is `checked-correct`.
  `existedBy`, `anchorNetwork` and `anchorNamespace` do not move: they come
  from `true` publications only. Both SDKs (TzunAI/tzun#21).
- `verifyBundle()` reads a `null` `chain`, `custody`, `anchoring` or
  `extensions` slot as one with nothing to carry (no chain id and no
  predecessor, no custody row, no anchoring material, no extension), as
  Bundle §3.1 allows; it refused each as `malformed_bundle`. It no longer
  refuses custody `entries` that are not objects, since the `bundle` row does
  not read custody material (TzunAI/tzun#23).

### Vectors

- `evm-anchor-vectors.json`: the 15 `validityBounds` entries whose `window` is
  `excludes` now give `expect.noHeader.canonical` as `checked-correct`, where
  they gave `not-checked`, `blocked_by:anchor.evm.tx` (§10.4 item 13). Nothing
  else that a verifier reads moves: `header` and `offline` keep `blocked`, and
  the publication, its block and every other case are as before. The
  description and four case names cite §9 for statements of §9, not §13, and
  the description no longer names header-source cases §13 does not list
  (TzunAI/tzun#21, TzunAI/tzun#22).
- `checkpoint-vectors.json`: descriptive members only. The `description`
  cites Anchor §4 to §6, §10.3, §10.6 and §10.7; `format.artifactExpect` says
  `anchorNamespace` is `'test'` once step 2's shape check holds and the anchor
  origin begins with `test.`; `format.domainRule` names `test.log.tzun.ai` as
  the namespace and `test.log.tzun.ai/<deploymentId>` as the domain prefix
  (TzunAI/tzun#22).
- `bundle-b1/`:
  - `custody-ledger`: `custody.ledger` abstains, `unsupported_artifact`; the
    summary moves one row from `checked-correct` to `abstain`; exit 4 (was 0).
    Its bundle and inputs are unchanged. `custody-row-removed` and
    `custody-row-and-mirror-removed` keep their rows and exits
    (TzunAI/tzun#23).
  - Four new cases give the record's anchor an `rfc3161/1` publication of its
    P from a second authority: `anchor-token-trusted` (exit 0),
    `anchor-token-no-roots` (exit 4), `anchor-token-other-value`
    (`imprint_mismatch`, exit 1) and `anchor-token-not-der`
    (`malformed_publication`, exit 1). They are built from the corpus's own
    bundles; no other case's files change (TzunAI/tzun#24).
  - `index.json`: the descriptions of `record-token-unreadable-certificate`
    (tzun-anchor/1 §10.5 step 1; Verification §4.4) and
    `fabricated-header-offline` (Anchor §10.4, §10.6) cite the sections that
    state them (TzunAI/tzun#22), and those of the custody cases say what the
    row now decides.

## [0.8.4] — 2026-10-15

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
  missing provider or base URL is `null`, as is a base URL with a `\` in its
  host part, which openai-node and httpx send to different hosts. A value the
  AI-BOM rules would refuse is recorded as `null` rather than failing the
  capture: `maxTokens` and `seed` are kept only as safe integers, an
  infrastructure string only up to 256 UTF-16 code units, and `stopSequences`
  only when there are at most 16 of at most 256 code units each (never
  truncated). The TypeScript and Python connectors record the same bytes for
  the same call.
- TypeScript: `tzun.attach()` detects an OpenAI-compatible client whose base
  URL host is `openrouter.ai` or a subdomain such as `eu.openrouter.ai` as
  `openrouter` and records its base URL; `wrapOpenRouter` pins the vendor for
  any base URL. `tzun.hook('openrouter', request, response)` records the
  endpoint passed as `request.openrouter_endpoint`. `SUPPORTED_VENDORS` has
  eight labels. The importer exports the `openRouterAuthor` and
  `openRouterVariantBase` id helpers.
- Python: the `openrouter` connector (`tzun_sdk.ai_bom.connectors.openrouter`,
  registry key `openrouter`), so `hook("openrouter", request, response)`
  works, with the endpoint passed as `request["openrouter_endpoint"]`.
  `attach()` detects an OpenAI client whose `base_url` host is `openrouter.ai`
  or a subdomain such as `eu.openrouter.ai` as `openrouter` and records its
  base URL; `vendor="openrouter"` pins the vendor for any base URL. It
  intercepts the same two methods as for `openai`, `chat.completions.create`
  and `responses.create`. `parse_model_id` gains the `openrouter` rule, and
  `openrouter_author` and `openrouter_variant_base` are the id helpers.
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
  `openrouter.ai` or a subdomain such as `eu.openrouter.ai` now registers a
  descriptor with `vendor: 'openrouter'`, the served id as `modelName`, and an
  `infrastructure` block, where it registered `vendor: 'openai'` with no
  infrastructure. This holds in both SDKs. Records already captured are
  unchanged and still verify. `tzun.attach(client, { vendor: 'openai' })`
  (TypeScript) and `attach(client, tzun=tzun, vendor="openai")` (Python) keep
  the old classification.

## [0.8.3] — 2026-10-15

### Added

- `readEvmTransaction` and `evmRlpForm` (`src/attestation/blockchain.ts`,
  exported from that module, not from the package entry) read a signed
  transaction as tzun-anchor/1 §10.4 item 2 does and report the rule it breaks;
  ethers supplies RLP decoding, keccak-256 and secp256k1 recovery, and no
  longer reads the transaction (`Transaction.from`). `decodeEvmTransaction`
  returns the transaction or `null`. In Python, `decode_signed_transaction`
  (`tzun_sdk.attestation.evm_transaction`) raises `EvmTransactionError` with
  the same rule as `.rule`, and `rlp_form` (`tzun_sdk.attestation.evm_rlp`) is
  `evmRlpForm`.
- `withLowS` and `transactionToBroadcast` (`src/anchoring/evm-chain.ts`,
  exported from that module, not from the package entry). `withLowS` is the
  high-`s` replacement, for a typed transaction or an EIP-155 legacy `v`, and
  `null` for a legacy `v` of 27 or 28. `transactionToBroadcast` is a signed
  transaction as it meets item 2: unchanged, with its `s` lowered, or the rule
  of item 2 it breaks. The checks of §7.2 rule 3, of the type, the chain id and
  the sender, are made in `checkSignedTransaction`.
- `vectors/evm-anchor-vectors.json` gains `transactionCases`: signed
  transactions at each edge of each rule of item 2, those it refuses and those
  just inside, each refused case with the one rule it breaks (`chain-id`,
  `legacy-v`, `signature-values`, `fees`, `recovery`, `encoding`,
  `field-sizes`), and the verdict for each. Each case states the `sender` and
  `signedChainId` that `anchor.evm.tx` reports once item 2 reads the
  transaction: `signedChainId` is the chain id in decimal, `null` for the two
  cases with `v` 27 and 28, and `null` for a refused case, which reports no
  facts. Its existing cases are unchanged.

### Changed

- The `evm-calldata/1` publication verifier (`verifyEvmPublication`,
  `verify_evm_publication`) applies the seven rules tzun-anchor/1 §10.4 item 2
  states for a transaction to decode and yield a sender, itself, before any
  signature is recovered. On the points those rules cover, the outcome and
  reason no longer depend on the Ethereum library a verifier uses; on other
  points they still can. Each of these is now `false`, `malformed_publication`,
  in both SDKs:
  - **Chain id**: a typed transaction (EIP-2930, EIP-1559) signed for chain id
    0;
  - **Legacy v**: a legacy `v` other than 27, 28, or `chainId * 2 + 35` or
    `+ 36` for a chain id of 1 or more, so `v` 35 and 36;
  - **Signature values**: `r` outside [1, n - 1], `s` outside [1, (n - 1) / 2]
    (EIP-2), or a typed `yParity` other than 0 or 1;
  - **Fees**: an EIP-1559 `maxPriorityFeePerGas` above its `maxFeePerGas`;
  - **Recovery**: a signature from which no public key recovers;
  - **Encoding**: a `rawTransaction` that is not the canonical RLP of its
    fields: an integer with a leading zero byte (0 must be the empty string),
    a single byte below `0x80` written as a one-byte string, a length not in
    its minimal form, or anything after the list;
  - **Field sizes**: a `nonce` or `gasLimit` above 2^64 - 1; a chain id,
    `value`, `gasPrice`, `maxPriorityFeePerGas` or `maxFeePerGas` above
    2^256 - 1; a legacy `v` above 2 * (2^256 - 1) + 36.

  Ethereum mainnet, Sepolia and Hoodi, the chains of the network table in §9,
  refuse such a transaction under the rules they apply today, so no block they
  produce today holds one, and refusing it refuses no publication made on
  them. A development chain can be more lenient: anvil, for one, mines a
  transaction whose `s` is above (n - 1) / 2. A publication on such a chain
  that breaks one of these rules is refused like any other. Before, ethers
  recovered a sender for a typed transaction on chain id 0, for a high `s`
  (read as `n - s`), for non-canonical RLP and for a `gasLimit` of 2^64 or
  more, so such a publication from a listed publisher could be
  `evm_chain_mismatch` or `true`; go-ethereum recovers one for a legacy `v` of
  35 or 36, for a tip above the fee cap, and for a `value` or fee of 2^256 or
  more, which ethers refuses. An unprotected legacy transaction (`v` 27 or 28)
  is read as before, and §10.4 item 5 refuses its chain. Types other than 0, 1
  and 2 abstain as before. See TzunAI/tzun-verify#37.
- The `signedChainId` fact of a legacy transaction whose `v` is 27 or 28,
  which signs no chain id (§10.4 item 2), is `null` in both SDKs, as
  tzun-anchor/1 §10.7 states and tzun-verify reports. It was `"0"`. The type
  is `string | null` (`EvmPublicationFacts.signedChainId`) and `str | None` in
  Python, and the `anchor.evm.tx` check of `verifyAnchor` and `verify_anchor`
  carries the `null`. The verdict is unchanged: such a transaction signs no
  chain id, so §10.4 item 5 matches it to no manifest entry
  (`evm_chain_mismatch`).
- The anchor scheduler sends only transactions that meet the seven rules of
  §10.4 item 2, read with the verifier's own reader, as tzun-anchor/1 §7.2
  rule 3 and §11 item 6 require of a writer. The Python SDK has no anchor
  writer.
  - It checks every transaction its signer returns before it stores or
    broadcasts it. This covers every signer path: a private key, an ethers
    `Signer`, and a KMS or HSM signer. A signature whose `s` is above
    (n - 1) / 2, which some KMS and HSM signers return, is replaced by the
    equivalent one, `s` as n - `s` with `yParity` flipped: the same key's
    signature over the same hash, from which the same sender recovers. The
    scheduler stores and broadcasts that transaction, whose id is not the one
    the signer returned. Before, it refused a high `s` as a signature
    mismatch and published nothing. A transaction that breaks any other rule
    (a chain id of 0, a tip above the fee cap, RLP that is not canonical, and
    so on) is neither stored nor broadcast: the pass fails with an
    `AnchorSignerError` whose `field` and new `rule` name the rule, and the
    `anchor_signer_mismatch` alarm. A transaction that meets every rule is
    stored and broadcast with its bytes unchanged. A transaction of a type
    item 2 does not read (3, 4 and so on) is refused for its `type`, and the
    error's message names the type and says item 2 does not read it. A high
    `s` on a legacy `v` of 27 or 28 is never lowered: such a transaction
    signs no chain id, and rule 3 requires one. A publisher passed to
    `createAnchorScheduler` as `publisher` returns the bytes that are sent,
    and nothing it returns is lowered: before anything it returns is stored
    or enrols the wallet, the scheduler reads it the same way. It must meet
    every rule as returned, a high `s` included, be of a type item 2 reads
    (another is refused for its `type`), sign the publisher's chain id,
    recover the publisher's address, be at the nonce asked for, and have the
    hash of its bytes as its hash. A publication must also carry the
    calldata 0x ‖ P and no value; an accounted transaction must go to the
    recipient, with the value and the calldata, asked for. A publication's
    recipient, and the gas and fees of either, are not compared. Otherwise
    it is refused with an `AnchorSignerError` and nothing is stored,
    enrolled or sent; a publication's pass fails with the
    `anchor_signer_mismatch` alarm and is retried, unless what it returned
    is the publication asked for and the publisher's window in the
    manifest closed while it signed: then the pass defers
    (`anchor_publisher_outside_window`). Before, what such a publisher
    returned was stored and broadcast as it was.
  - It checks the bytes it is about to send on every broadcast, a stored
    transaction sent again included: they must meet every rule, sign the
    publisher's chain id, and recover the sender authenticated for the
    publication, or the wallet for an accounted transaction (`sweep`,
    `handover`). A publication's bytes must also carry the nonce and the
    calldata, 0x ‖ P, it was signed or authenticated with this pass, not
    those of a row read since, and no value: another transaction of the same
    key, at another nonce, over other calldata or with a value, is not sent
    in its place. Anyone who can write the store can replace a stored
    transaction, without the key, with its twin (`s` as n - `s`, the parity
    flipped) or with its values in RLP that is not canonical; both recover the
    same sender, and every verifier refuses both. Such bytes are not sent and
    never lowered or repaired, since a stored attempt is append-only:
    `anchor_publication_unexplained`, or `anchor_wallet_tx_unexplained` for an
    accounted transaction, stops anchoring. Before, a stored transaction was
    sent again as it was stored.
  - It accepts an earlier publication as its own only when item 2 reads each
    of its transactions: the publication checks read them with
    `readEvmTransaction`, which supplies the sender, chain id and calldata;
    ethers, which recovers the same sender from either twin, reads only the
    nonce, value and fee caps of bytes item 2 has already read.
    `assertAnchorWalletTx`, which the SQLite and Postgres stores run on every
    accounted transaction they insert and the scheduler on every one it reads,
    refuses one that item 2 does not read, naming the rule, and takes its
    sender and chain id from item 2's reading.

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

- A transaction with a `nonce` from 2^53 to 2^64 - 1 is read and its sender
  recovered. An account's nonce is a 64-bit integer, so a nonce above 2^53 - 1
  can be real; the SDKs refused it as `malformed_publication` only because
  ethers reads a nonce as a JavaScript safe integer (the Python SDK copied
  that limit). A legacy `v` above 2^256 - 1 (a chain id of about 2^255 or
  more) is read for the same reason.
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
